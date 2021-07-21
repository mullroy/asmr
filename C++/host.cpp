#include <stdio.h>
#include <unistd.h>
#include <string> 
#include <string.h>
#include <cstdlib>
#include <cstdint>
#include "main.h"

// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include "libasmr.h"

#define PORT     8080
#define MAX_ITEM_LENGTH 256*1024
int sockfd;
struct sockaddr_in servaddr, cliaddr;

char receive_network (char *pcCmd, unsigned char *pcaData, int *piLength)
{
  unsigned int iLength;

  char cNetworkData[MAX_ITEM_LENGTH+5];
  
  *piLength=0;
  *pcCmd=-1;
  unsigned int len = sizeof(cliaddr);  //len is value/resuslt
 
  printf("Waiting for network input:\n"); 
  int n = recvfrom(sockfd, &cNetworkData[0], MAX_ITEM_LENGTH+5,
                   MSG_WAITALL, (struct sockaddr *) &cliaddr,
                   &len);
  //printf("n=%d\n",n);
  if (n>0)
  {
     //printf("Have data:\n");
     memcpy ( (char *)&iLength, &cNetworkData[0], 4);
     if ( (iLength+5) == n)
     {
       //printf("Assign data\n");
       *pcCmd = cNetworkData[4];
       memcpy( pcaData, &cNetworkData[5], iLength);
       *piLength = iLength;
       return 1;
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
  char    cReturnCode;
  
  char cCmd, cResponse;
  unsigned char caNetworkData[MAX_ITEM_LENGTH];
  int iLength;
      
  //printf("Spawn host\n");
  //------------------------------------------------
  cReturnCode = asmr_spawn_host( );
  if(cReturnCode != 0)
  {
    printf("Could not spawn the host\n");
    exit(0);
  }
  //printf("host spawned\n");
  
  
  printf("Open network port\n");
  // Creating socket file descriptor
  if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) 
  {
    printf("socket creation failed\n");
    exit(EXIT_FAILURE);
  }
      
  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));
      
  // Filling server information
  servaddr.sin_family    = AF_INET; // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(PORT);
      
  // Bind the socket with the server address
  if ( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 )
  {
    printf("Could not bind socket to the port\n");
    exit(EXIT_FAILURE);
  }
      
  int n;
  unsigned int len = sizeof(cliaddr);  //len is value/resuslt
  
  
  //Exchange network handshake:
  printf("Waiting for handshake from client\n");
  while(1)
  {
    usleep(1000000);
    
    char cReturnCode = receive_network (&cCmd, &caNetworkData[0], &iLength);
    if (cReturnCode == 1)
    {
      if (cCmd!=0)
      {
        printf("Expected handshake command. Received command: 0x%02x\n",cCmd);
        exit(EXIT_FAILURE);
      }
      if ( strncmp( (char *)&caNetworkData[0], "ASMR", 4) == 0)
      {
        printf("Received handshake from client\n");
        
        iLength=11;
        memcpy(&caNetworkData[0], (char *)&iLength, 4);
        caNetworkData[4]=0;//cmd

        caNetworkData[5]='C';//ConfirmASMR
        caNetworkData[6]='o';
        caNetworkData[7]='n';
        caNetworkData[8]='f';
        caNetworkData[9]='i';      
        caNetworkData[10]='r';
        caNetworkData[11]='m';
        caNetworkData[12]='A';
        caNetworkData[13]='S';
        caNetworkData[14]='M';
        caNetworkData[15]='R';
      
        //printf("transmit\n");
        sendto(sockfd, &caNetworkData[0], iLength+5, 
             MSG_CONFIRM, (const struct sockaddr *) &cliaddr,
             len);
        
        break;
      }     
      else
      {
        printf("Handshake with host failed.\n");
        exit(EXIT_FAILURE);
      }
    }
  }
  
  //Process host states:
  int iBTCFunded=0;
  int iCounter;
  while(1)
  {
    usleep(1000000);
    
    cReturnCode = asmr_read (&cCmd, &caNetworkData[0], &iLength);
    if (cReturnCode == 1)
    {
      if (cCmd == 1) //Send host verification key to client
      {
        //Store the data in a local shared file instead of sending the data
        //over the network. Actual implementation needs to send data over the network.
        FILE *fp = fopen("host_client.bin","wb");
        fwrite(&caNetworkData[0],1, iLength, fp);
        fclose(fp);
        
        //printf("#1: Send %u bytes to client\n",iLength);
        sendto(sockfd, &cCmd, 1, 
         MSG_CONFIRM, (const struct sockaddr *) &cliaddr,
         len);         
        
        //printf("#1: Waiting for client to respond with the client_key\n");
        iCounter=0;
        while(1)
        {
          cReturnCode = receive_network (&cCmd, &caNetworkData[0], &iLength);
          if (cReturnCode == 1)
          {
            if (cCmd!=1)
            {
              printf("Expected response for cmd=1 is cmd=1. Received %d\n",cCmd);
              break;
            }
            FILE *fp;
            fp = fopen("client_host.bin","rb");
            iLength = fread(&caNetworkData,1,MAX_ITEM_LENGTH,fp);
            //printf("#1 Received client response: cmd=%d len=%d",cCmd,iLength);
            
            //Cmd=1: Send the client key to the library:
            cReturnCode = asmr_write (&cCmd, &caNetworkData[0], &iLength);
            if (cReturnCode != 1)
            {
              printf("#1 Could not provide the data to the library\n");          
            }            
            
            
            break;
          }
          usleep(100000);
          iCounter++;
          if (iCounter>=100) //10 second
          {
            printf("#1 Did not get a response from the library after 10 seconds\n");
            break;
          }
        }
      }
      else if ( (cCmd==2) ||  //Send host & client key CRCs for verification
                (cCmd==4) ||  //Send signature
                (cCmd==5) ||  //Send signatures CRCs for verification 
                (cCmd==7) ||  //Send client buy-from-lock transaction
                (cCmd==8) ||  //Send client: BTC funds locked?
                (cCmd==9) ||  //Send client: Arrr account funded?
                (cCmd==11)||  //Send secret
                (cCmd==13) )  //Transaction complete
      {
        //Build network packet: 0..3 : Length, 4 : Cmd, 5... :Data        
        //Move data by 5 bytes:
        for (int iI=iLength-1;iI>-1;iI--)
        {
          caNetworkData[iI+5] = caNetworkData[iI];
        }
        memcpy(&caNetworkData[0], (char *)&iLength, 4);
        caNetworkData[4] = cCmd;
        iLength+=5;
        
        //printf("#%d: Send %u bytes to client\n",cCmd, iLength);
        sendto(sockfd, &caNetworkData[0], iLength,
         MSG_CONFIRM, (const struct sockaddr *) &cliaddr,
         len);
        
        //printf("#%d: Waiting for client to respond\n", cCmd);
        iCounter=0;
        while(1)
        {
          cReturnCode = receive_network (&cResponse, &caNetworkData[0], &iLength);
          if (cReturnCode == 1)
          {
            if (cResponse!=cCmd)
            {
              printf("Expected response for cmd=%d is cmd=%d. Received %d\n",cCmd,cCmd,cResponse);
              continue;
            }
          
            if (cResponse != 13)
            {
              //printf("asmr_write: cmd=%d, length=%d\n",cCmd, iLength);  
              //Send the client response to the library:
              cReturnCode = asmr_write (&cCmd, &caNetworkData[0], &iLength);
              if (cReturnCode != 1)
              {
                printf("HOST: #%d: Could not provide the data to the library\n",cCmd);
              }            
            }           
            else
            {
              //Transaction complete and communicatino finished with client
              printf("HOST: #13 Transaction complete\n");
              break;
            }
            break;
          }
          usleep(100000);
          iCounter++;
          if (iCounter>=100) //10 second
          {
            printf("#2: Did not get a response from the client after 10 seconds\n");
            break;
          }
        }      
        
        if (cResponse==13)
        {
          break;
        }
      }
      else if (cCmd==3) //BTC account funded?
      {
        caNetworkData[ iLength] = 0;
        //printf("HOST: #3 BTC account funded?\n%s\n", (char *)&caNetworkData[0]);
        
        //3 expected resonses:
        //Fund BTC address {}
        char *pResult = strstr( (char *)&caNetworkData[0], "Fund BTC address ");
        if (pResult != 0)
        {
          if (iBTCFunded!=1)
          {
            printf("HOST: #3 %s\n",&caNetworkData[0]);
          }
          iBTCFunded=1;
        }
        else
        {
          //Detected funds for address {}        
          char *pResult = strstr( (char *)&caNetworkData[0], "Detected transaction for address ");
          if (pResult != 0)
          {
            printf("HOST: #3 %s\n",&caNetworkData[0]);
          }          
          else
          {
            //BTC address {} funded
            char *pResult = strstr( (char *)&caNetworkData[0], "BTC address ");
            if (pResult != 0)
            {
              printf("HOST: #3 %s\n",&caNetworkData[0]);
            }
          }
        }
      }
      //else
      //{
      //  printf("read_host(): cCmd=%x iLength=%x\n",cCmd, iLength);
      //}
    }
  }
  
  return 0;
}