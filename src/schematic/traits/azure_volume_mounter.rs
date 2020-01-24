use k8s_openapi::api::core::v1 as core;
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as meta;
use kube::client::APIClient;
use kube::api::{Api};
use serde_json::map::Map;
use log::{warn};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use k8s_openapi::api::apps::v1 as apps;

use crate::schematic::{
    component::{Component},
    traits::util::{OwnerRefs, TraitResult},
    traits::TraitImplementation,
};
use std::collections::BTreeMap;

/// The AzureVolumeMounter trait provisions volumes that can
/// be mounted by a Component.
#[derive(Clone, Debug)]
pub struct AzureVolumeMounter {
    /// The app configuration name
    pub name: String,
    /// The instance name for this component
    pub instance_name: String,
    /// The component name
    pub component_name: String,
    /// The owner reference (usually of the component instance).
    /// This should be attached to any Kubernetes resources that this trait creates.
    pub owner_ref: OwnerRefs,
    /// The component that we are attaching to
    pub component: Component,
    /// The name
    pub volume_name: String,
    /// The name of the Azure storage account
    pub storage_account_name: String,
    /// The name of the Azure storage key
    pub storage_account_key: String,
    /// The name of share from the Azure storage account to mount
    pub share_name: String,
    /// Mount point (RO/RW)
    pub is_read_only : bool,
}

impl AzureVolumeMounter {
    pub fn from_properties(
        name: String,
        instance_name: String,
        component_name: String,
        properties_map: Option<&Map<String, serde_json::value::Value>>,
        owner_ref: OwnerRefs,
        component: Component,
    ) -> Self {
        let instancename = instance_name.clone();
        AzureVolumeMounter {
            name,
            component_name,
            instance_name,
            owner_ref,
            component,
            volume_name: properties_map
                        .and_then(|map| map.get("volumeName").and_then(|p| p.as_str()))
                        .unwrap_or_else( || { warn!("Unable to parse volumeName value for instance:{}. Setting it to default value:empty", instancename); "" } )
                        .to_string(),
            storage_account_name: properties_map
                        .and_then(|map| map.get("storageName").and_then(|p| p.as_str()))
                        .unwrap_or_else( || { warn!("Unable to parse storageName value for instance:{}. Setting it to default value:empty", instancename); "" } )
                        .to_string(),
            storage_account_key: properties_map
                        .and_then(|map| map.get("storageKey").and_then(|p| p.as_str()))
                        .unwrap_or_else( || { warn!("Unable to parse storageKey value for instance:{}. Setting it to default value:empty", instancename); "" } )
                        .to_string(),
            share_name: properties_map
                        .and_then(|map| map.get("shareName").and_then(|p| p.as_str()))
                        .unwrap_or_else( || { warn!("Unable to parse storageKey value for instance:{}. Setting it to default value:empty", instancename); "" } )
                        .to_string(),
            is_read_only: properties_map
                          .and_then(|map| map.get("isReadOnly").and_then(|p | p.as_bool()))
                          .unwrap_or(true),
        }
    }
    fn labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), self.name.clone());
        labels.insert("component-name".to_string(), self.component_name.clone());
        labels.insert("instance-name".to_string(), self.instance_name.clone());
        labels.insert("trait".to_string(), "azure-volume-mounter".to_string());
        labels
    }
    fn secret_name(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.storage_account_key.hash(&mut hasher);
        format!("{}-{}-{}", self.instance_name, self.storage_account_name, hasher.finish())
    }
    fn deployment_name(&self) -> String {
        self.instance_name.clone()
    }
    fn create_metadata(
        &self,
        name: String,
        labels: BTreeMap<String, String>,
        owner_references: Option<Vec<meta::OwnerReference>>,
    ) -> Option<meta::ObjectMeta> {
        Some(meta::ObjectMeta {
            name: Some(name),
            labels: Some(labels),
            owner_references,
            ..Default::default()
        })
    }
    fn to_secret(&self) -> core::Secret {
        let mut secret_string_map : BTreeMap<String, String> = BTreeMap::new();
        secret_string_map.insert("azurestorageaccountname".into(), self.storage_account_name.clone());
        secret_string_map.insert("azurestorageaccountkey".into(), self.storage_account_key.clone());
        core::Secret {
            metadata: Some(meta::ObjectMeta {
                name: Some(self.secret_name().clone()),
                labels: Some(self.labels()),
                owner_references: self.owner_ref.clone(),
                ..Default::default()
            }),
            string_data : Some(secret_string_map),
            ..Default::default()
        }
    }
    fn update_deployment(&self, ns: &str, client: APIClient) -> TraitResult {
        let deployment_name = self.deployment_name();
        let deps = Api::v1Deployment(client.clone()).within(ns);
        let p = deps.get(deployment_name.as_str())?;
        let mut deploymentspec = p.spec.clone() as apps::DeploymentSpec;
        let deployment_metadata = p.metadata.clone();
        let mut pod_spec : core::PodSpec = p.spec.template.spec.clone().unwrap();
        let podspec_metadata = p.spec.template.metadata.clone().unwrap();
        let mut vols = vec![];
        vols.push(core::Volume {
            azure_file: Some(core::AzureFileVolumeSource {
            read_only : Some(self.is_read_only),
            secret_name : self.secret_name(),
            share_name : self.share_name.clone()
            }),
            name: self.volume_name.to_string(),
            ..Default::default()
        });
        pod_spec.volumes = Some(vols);
        deploymentspec.template.spec = Some(pod_spec);
        deploymentspec.template.metadata = Some(podspec_metadata.clone());
        let patch_deployment = apps::Deployment {
            metadata: self.create_metadata(
                deployment_name.clone(),
                deployment_metadata.labels.clone(),
                None,
            ),
            spec: Some(deploymentspec),
            ..Default::default()
        };
        let pp = kube::api::PatchParams::default();
        kube::api::Api::v1Deployment(client.clone())
            .within(ns)
            .patch(deployment_name.clone().as_str(), &pp, serde_json::to_vec(&patch_deployment)?)?;
        Ok(())
    }
}

impl TraitImplementation for AzureVolumeMounter {
    /// Make sure the secret for connecting to Azure storage is created before the Pod.
    fn pre_add(&self, ns: &str, client: APIClient) -> TraitResult {
        let secret = self.to_secret();
        let (req, _) = core::Secret::create_namespaced_secret(
            ns,
            &secret,
            Default::default())?;
        client.request::<core::Secret>(req)?;
        Ok(())
    }
    fn add(&self, ns: &str, client: APIClient) -> TraitResult {
        self.update_deployment(ns, client)?;
        Ok(())
    }
    fn modify(&self, ns: &str, client: APIClient) -> TraitResult {
        let secret = self.to_secret();
        let values = serde_json::to_value(&secret)?;
        let (req, _) = core::Secret::patch_namespaced_secret(
            self.secret_name().clone().as_str(),
            ns,
            &meta::Patch::StrategicMerge(values),
            Default::default(),
        )?;
        client.request::<core::Secret>(req)?;
        self.update_deployment(ns, client)?;
        Ok(())
    }
    fn delete(&self, ns: &str, client: APIClient) -> TraitResult {
        let (req, _) = core::Secret::delete_namespaced_secret(
            self.secret_name().clone().as_str(),
            ns,
            Default::default(),
        )?;
        client.request::<core::Secret>(req)?;
        Ok(())
    }
    fn status(&self, ns: &str, client: APIClient) -> Option<BTreeMap<String, String>> {
        let secret_name = self.secret_name().clone();
        let key = format!("secret/{}", secret_name);
        let mut resource = BTreeMap::new();
        let req = core::Secret::read_namespaced_secret(
            secret_name.as_str(),
            ns,
            Default::default(),
        );
        if let Err(err) = req {
            resource.insert(key, err.to_string());
            return Some(resource);
        }

        let (raw_req, _) = req.unwrap();
        match client.request::<core::Secret>(raw_req) {
            Ok(_secret) => {
                resource.insert(
                    key,
                    "created".to_string()
                );
            }
            Err(e) => {
                resource.insert(key, e.to_string());
            }
        };
        Some(resource)
    }
}