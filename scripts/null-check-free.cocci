//
// No null check required before calling free()
//

@@
expression E;
@@
(
-if (E) { free(E); }
+free(E);
|
-if (E != NULL) { free(E); }
+free(E);
)
