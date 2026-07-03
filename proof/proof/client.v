From New.proof.github_com.sanjit_bhat.pav.client_proof Require Export
  base client rpc_serv.

Module Import client.
  Export base.client client.client rpc_serv.client.
End client.
