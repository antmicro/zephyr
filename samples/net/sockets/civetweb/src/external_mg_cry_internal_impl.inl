static void mg_cry_internal_impl(const struct mg_connection *conn,
                                 const char *func,
                                 unsigned line,
                                 const char *fmt,
                                 va_list ap)
{
	(void)conn;
	(void)func;
	(void)line;
	(void)fmt;
	(void)ap;
	printf("[INTERNAL ERROR]: %s @ %d\n", func, line);
	vprintf(fmt, ap);
	printf("\n");
}
