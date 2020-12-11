printf("Out?\n");
SSL *ssl;
ssl = SSL_new(serv_ctx);
SSL_set_fd(ssl, i);
SSL_set_accept_state(ssl);
X509 *cert = SSL_get_certificate(ssl);
if (cert) {
char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
printf("Subj: %s\nIssuer: %s\n", subj, issuer);
}
printf("Before..\n");
if (SSL_accept(ssl) <= 0) {
  ERR_print_errors_fp(stderr);
  printf("Bad ssl accepnt\n");
  exit(1);
}
printf("DID THIS WORK???\n");
char sslbuf[BUFSIZE] = {0};
int bytes = SSL_read(ssl, sslbuf, BUFSIZE);
if (bytes > 0) {
  buf[bytes] = '\0';
  printf("Read message: %s\n", sslbuf);
  SSL_write(ssl, "no way\n", 7);
  SSL_free(ssl);
  close(i);
  FD_CLR(i, &master_set);
}
