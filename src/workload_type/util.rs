use k8s_openapi::api::core::v1 as core;
use kube::client::APIClient;
use log::{warn};

pub fn list_pvc_names(namespace: String, client: APIClient) -> Result<Vec<String>, String>
{
    let req = core::PersistentVolumeClaim::list_namespaced_persistent_volume_claim(
        namespace.as_str(),
        Default::default(),
    );
    if let Err(e) = req {
        return Err(e.to_string())
    }
    let (raw_req, _) = req.unwrap();
    match client.request::<core::PersistentVolumeClaimList>(raw_req) {
        Ok(pvclist_response) => {
            let mut names : Vec<String> = pvclist_response.items.into_iter().map(|item| item.metadata.map(|m| m.name.unwrap_or_else(String::new)).unwrap_or_else(String::new)).collect();
            names = names.into_iter().filter(|v| !v.is_empty()).collect::<Vec<_>>();
            Ok(names)
        }
        Err(e) => {
            warn!("Quering for pvc failed for namespace:{} with error: {}", namespace, e.to_string());
            Err(e.to_string())
        }
    }
}
