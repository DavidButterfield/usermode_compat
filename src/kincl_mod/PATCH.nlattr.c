--- klib/nlattr.c	2019-07-01 13:25:25.153552216 -0600
+++ klib/nlattr.c	2019-07-01 13:24:57.345631662 -0600
@@ -411,7 +411,8 @@
 	struct nlattr *nla;
 
 	nla = __nla_reserve(skb, attrtype, attrlen);
-	memcpy(nla_data(nla), data, attrlen);
+	if (attrlen)
+	    memcpy(nla_data(nla), data, attrlen);
 }
 EXPORT_SYMBOL(__nla_put);
 
