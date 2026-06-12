# VL Kubernetes Range (k3s)

Single-node k3s cluster for the **Container / Kubernetes** module and
`vuln` tier9_iac / tier10_cloud_native (live-cluster tiers: kube-hunter,
RBAC audit, kubeconfig-based probes).

## Bring it up

```bash
docker compose up -d lab_k3s
sleep 25            # k3s needs ~20s to write its kubeconfig
```

k3s writes its kubeconfig to this directory (`labs/vl_k8s_range/kubeconfig.yaml`)
via the bind mount. Its server URL defaults to `https://127.0.0.1:6443`, which
the backend container can't reach — rewrite it to the container hostname:

```bash
sed -i 's#https://127.0.0.1:6443#https://lab_k3s:6443#' labs/vl_k8s_range/kubeconfig.yaml
```

(The cert already carries `lab_k3s` as a SAN via `--tls-san lab_k3s`, so TLS
verifies.)

## Use it

Open the **Container / Kubernetes** module → Configure & Scan → paste the
contents of `kubeconfig.yaml` into the **kubeconfig** input, then Start.

For the static tiers (Trivy / Grype / Syft / Hadolint / checkov) you don't
need the cluster at all — use the **image_ref**, **Dockerfile**, and
**pod YAML** presets in the same modal.

> The generated `kubeconfig.yaml` is git-ignored — it holds a cluster admin
> credential. Never commit it.
