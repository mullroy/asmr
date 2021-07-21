#include <stdio.h>
#include <unistd.h>
#include <string> 
#include <string.h>
#include <cstdlib>
#include <cstdint>
#include "main.h"

// Client side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#include "libasmr.h"

#define MAX_ITEM_LENGTH 256*1024
int sockfd;
struct sockaddr_in servaddr, cliaddr;

char receive_network (char *pcCmd, unsigned char *pcaData, int *piLength)
{
  unsigned int iLength;

  char cNetworkData[MAX_ITEM_LENGTH+5];
  
  *piLength=0;
  *pcCmd=-1;
  unsigned int len = sizeof(servaddr);  //len is value/resuslt
  
  int n = recvfrom(sockfd, &cNetworkData[0], MAX_ITEM_LENGTH+5,
                   MSG_WAITALL, (struct sockaddr *) &servaddr,
                   &len);
  if (n>5)
  {
     memcpy ( (char *)&iLength, &cNetworkData[0], 4);
     if ( (iLength+5) == n)
     {
       *pcCmd = cNetworkData[4];
       memcpy( pcaData, &cNetworkData[5], iLength);
       *piLength = iLength;
       
       return 1;
     }
     else
     {
       printf("CLIENT: Length field doesn't match nr of received bytes\n");
     }
  }
  if (n==1)
  {
    *pcCmd = cNetworkData[0];
    *piLength = 0;
    return 1;
  }
  return 0;
}

int main()
{
  int16_t iReturnCode; 
  uint8_t cSize;
  
  char cCmd,cResponse;
  unsigned char caNetworkData[MAX_ITEM_LENGTH];
  int iLength;
    
  //printf("Spawn client\n");
  char cReturnCode = asmr_spawn_client( );
  if(cReturnCode != 0)
  {
    printf("CLIENT: Could not spawn the client\n");
    exit(0);
  }
  //printf("client spawned\n");
  

  //Network
  //-------------------------------------------------------  
  printf("CLIENT: Open network port\n");
  #define PORT     8080
      
  // Creating socket file descriptor
  if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) 
  {
    printf("CLIENT: socket creation failed\n");
    exit(EXIT_FAILURE);
  }
      
  memset(&servaddr, 0, sizeof(servaddr));
      
  // Filling server information
  servaddr.sin_family    = AF_INET; // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(PORT);
      
      
  //Handshake:
  //-------------------------------------------------------
  iLength=4;
  memcpy( (char *)&caNetworkData[0], (char *)&iLength, 4);
  caNetworkData[4]=0;//cmd

  caNetworkData[5]='A';//ASMR
  caNetworkData[6]='S';
  caNetworkData[7]='M';
  caNetworkData[8]='R';
  
  printf("CLIENT: Transmit handshake to host\n");  
  sendto(sockfd, &caNetworkData[0], iLength+5,
         MSG_CONFIRM, (const struct sockaddr *) &servaddr, 
         sizeof(servaddr));
  
  //printf("Receive\n");    
  cReturnCode = receive_network (&cCmd, &caNetworkData[0], &iLength);
  if (cReturnCode == 1)
  {
    if ( strncmp( (char *)&caNetworkData[0], "ConfirmASMR", 11) == 0)
    {
      printf("CLIENT: Successful handshake with host\n");
    }     
    else
    {
      printf("CLIENT: Handshake with host failed.\n");
      exit(EXIT_FAILURE);
    }
  }

  int iCounter=0;  
  while(1)
  {
    cCmd=-1;
    cReturnCode = receive_network (&cCmd, &caNetworkData[0], &iLength);
    if (cReturnCode == 1)
    {
      if (cCmd==1) //Exchange keys: Host verifier key
      {
        printf("CLIENT: #1 Host verifier key received. Len:");
        
        FILE *fp;
        fp = fopen("host_client.bin","rb");
        iLength = fread(&caNetworkData,1,MAX_ITEM_LENGTH,fp);
        //printf("%d",iLength);
        
        cReturnCode = asmr_write (&cCmd, &caNetworkData[0], &iLength);
        if (cReturnCode != 1)
        {
          printf("CLIENT: #1 Could not provide the data to the library\n");          
        }
        
        iCounter=0;
        while(1)
        {
          //Have to wait for the library thread to pick up the command and process it.
          //The result is then available to retrieve.
          usleep(100000); //Wait 100ms
          cReturnCode = asmr_read (&cCmd, &caNetworkData[0], &iLength);
          if (cReturnCode == 1)
          {
            //printf("asmr_read(): cmd: %d, length:%d\n",cCmd, iLength);
            
            FILE *fp = fopen("client_host.bin","wb");
            fwrite(&caNetworkData[0],1, iLength, fp);
            fclose(fp);

            cCmd=1;
            //printf("SEND 1: cmd=%d, len=%u\n",cCmd,iLength);
            unsigned int len = sizeof(servaddr);  //len is value/resuslt            
            sendto(sockfd, &cCmd, 1,
                   MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                   len);
            break;
          }
          iCounter++;
          if (iCounter>=20) //2 second
          {
            printf("CLIENT: #1 Did not get a response from the library after 2 seconds\n");
            break;
          }
        }
      }            
      else if ( (cCmd==2) || //Verify host/client keys
                (cCmd==4) || //Exchange signatures
                (cCmd==5) || //Verify signatures
                (cCmd==7) || //Client buy-from-lock transaction
                (cCmd==8) || //Client: BTC funds locked?
                (cCmd==9) || //Arrr account funded?
                (cCmd==11)|| //Shared secret
                (cCmd==13) ) //Transaction complete
      {
        if (cCmd==2)
          printf("CLIENT: #2 Verify keys\n");
        if (cCmd==4)
          printf("CLIENT: #4 Exchange signatures\n");
        if (cCmd==5)
          printf("CLIENT: #5 Verify signatures\n");
        if (cCmd==7)
          printf("CLIENT: #7 Client buy-from-lock transaction\n");
        if (cCmd==8)
          printf("CLIENT: #8 BTC funds locked?\n");
        if (cCmd==9)
          printf("CLIENT: #9 Arrr account funded?\n");
        if (cCmd==11)
          printf("CLIENT: #11 Shared secret\n");
        if (cCmd==13)
        {
          printf("CLIENT: #13 Transaction complete\n");

          caNetworkData[0]=13;
          iLength=1;          
          unsigned int len = sizeof(servaddr);  //len is value/resuslt            
          sendto(sockfd, &caNetworkData[0], iLength,
                 MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                 len);
          break;
        }
          
          
        
        cReturnCode = asmr_write (&cCmd, &caNetworkData[0], &iLength);
        if (cReturnCode != 1)
        {
          printf("CLIENT: #%d Could not provide the data to the library\n",cCmd);
          continue;
        }
        
        iCounter=0;
        while(1)
        {
          //Have to wait for the library thread to pick up the command and process it.
          //The result is then available to retrieve.
          usleep(100000); //Wait 100ms
          cReturnCode = asmr_read (&cResponse, &caNetworkData[0], &iLength);
          if (cReturnCode == 1)
          {
            if (cResponse != cCmd)
            {
              //printf("CLIENT: #%d Race condition. Response=%d. Reread response\n",cCmd, cResponse);
              continue;
            }
            for (int iI=iLength-1;iI>-1;iI--)
            {
              caNetworkData[iI+5] = caNetworkData[iI];
            }
            memcpy(&caNetworkData[0], (char *)&iLength, 4);
            caNetworkData[4] = cResponse;
            iLength+=5;


            //printf("#%d SEND response=%d, len=%u\n",cCmd,cResponse,iLength);
            unsigned int len = sizeof(servaddr);  //len is value/resuslt            
            sendto(sockfd, &caNetworkData[0], iLength,
                   MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                   len);
            break;
          }
          char bSendTimeout=0;
          iCounter++;
          if (
             (cCmd==8) ||
             (cCmd==9)
             )
          {
            if (iCounter>=200) //20 second
            {
              printf("CLIENT: #%d Did not get a response from the library\n",cCmd);
              bSendTimeout=1;
            }
          }
          else
          {
            if (iCounter>=20) //2 second
            {
              printf("CLIENT: #%d Did not get a response from the library\n",cCmd);
              bSendTimeout=1;
            }
          }
          if (bSendTimeout==1)
          {
            //Respond with data[0]=0: "No response received"
            iLength=2;
            cResponse=0;
            memcpy(&caNetworkData[0], (char *)&iLength, 4);
            caNetworkData[4] = cCmd;
            caNetworkData[5] = 0x30; // 2x Ascii '0': No response from library
            caNetworkData[6] = 0x30; // 2x Ascii '0': No response from library            
            iLength+=5;
            
            unsigned int len = sizeof(servaddr);  //len is value/resuslt            
            sendto(sockfd, &caNetworkData[0], iLength,
                   MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                   len);          
            break;
          }
        }
      }
    }
    usleep(1000000);
  }

  printf("Done\n");  
  return 0;
}

