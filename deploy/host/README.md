# ATIBON Host Protection

This profile adds a Linux host enforcement layer through nftables.

## Safety
Do not apply the baseline blindly to a remote server. The default policy allows SSH 22, HTTP 80 and HTTPS 443 only. Add every required management/application port before activation.

## Install
1. Build: cargo build --release -p atibon-core --bin atibon-agent
2. Copy target/release/atibon-agent to /usr/local/bin/atibon-agent.
3. Review deploy/host/atibon.nft.
4. Validate: sudo nft -c -f deploy/host/atibon.nft
5. Copy the reviewed ruleset to /etc/atibon/atibon.nft.
6. Enable: sudo systemctl enable --now atibon-agent.service

## Rollback
Before activation, save the current ruleset with:
sudo nft list ruleset > /var/lib/atibon/pre-atibon.nft
Restore it with:
sudo nft -f /var/lib/atibon/pre-atibon.nft

Use shadow/observe-only operation before enforcing a new policy on production systems.
