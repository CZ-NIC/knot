//
// Remove third argument from knot_rrset_deep_free{,no_sig}() calls
//

@@
expression E1, E2, E3;
@@
(
 knot_rrset_deep_free
|
 knot_rrset_deep_free_no_sig
)
 (E1, E2
- , E3
 )
