//
// Use UNUSED(var) macro instead of casting expression to void.
//

@@
expression E;
@@
(
-(void)E;
+UNUSED(E);
)
