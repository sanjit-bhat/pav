From New.proof.github_com.sanjit_bhat.pav.auditor_proof Require Export
  auditor base rpc rpc_serv serde.

Module Import auditor.
  Export auditor.auditor base.auditor rpc.auditor rpc_serv.auditor serde.auditor.
End auditor.
