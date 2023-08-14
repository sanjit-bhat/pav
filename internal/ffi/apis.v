(* TODO: add predicates to this.
Set predicate on register. *)
(* Register: adds sign/verify keys to map.
keys = map[VerKey]SignKey
keys[sk] = pk
*)
Lemma wp_register :
    {{{ sk ∉ keys }}}
    register sk pk
    {{{ ret #NONE, sk ∈ keys }}}

(* Sign: adds signatures to a map.
sigs = make(map[SignKey][](data, sig))
sigs[SignKey] = append(sigs[SignKey], (data, sig)) *)
Lemma wp_sign :
    {{{ sk ∈ keys }}}
    Sign sk data
    {{{ ret #SOMEV (data, sig), sk ↦ [(data, sig); sk'] }}}

Lemma wp_sign' :
    {{{ sk ∈ keys }}}
    Sign sk data
    {{{ ret #SOMEV sig, (data, sig) ∈ sk(vk) }}}

(* Verify: checks map for signature.
return (data, sig) in signs[keys[vk]] *)
Lemma wp_verify_true :
    {{{ vk ∈ keys ∧ (data, sig) ∈ sk(vk) }}}
    Verify vk data sig 
    {{{ ret #true }}}

Lemma wp_verify_false :
    {{{ vk ∈ keys ∧ (data, sig) ∉ sk(vk) }}}
    Verify vk data sig 
    {{{ ret #false}}}

(* Hash: checks hash map.
hashes = map[data]val
val, ok = hashes[data]
if ok {
    return val
} else {
    hashes[data] = new(val)
}
*)
Lemma wp_hash_exists :
    {{{ data ∈ h ∧ val = h[data] }}}
    Hash data
    {{{ ret #SOMEV val }}}

Lemma wp_hash_new :
    {{{ data ∉ h }}}
    Hash data
    {{{ ret #SOMEV val, val = h[data] }}}
