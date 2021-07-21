#ifdef __cplusplus
extern "C" {
#endif
  extern char asmr_read (char *pcCmd, unsigned char *pcaData, int *piLength);
  extern char asmr_write(char *pcCmd, unsigned char *pcaData, int *piLength);

  extern char asmr_spawn_host( );
  extern char asmr_spawn_client( );
  
#ifdef __cplusplus
}
#endif