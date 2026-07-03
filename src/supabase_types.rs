///Row from the `tenants` table
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Tenants {
    /** Note:
This is a Primary Key.<pk/>*/
    pub id: uuid::Uuid,
    pub api_key_hash: String,
    pub created_at: String,
    pub name: String,
    pub cognee_dataset_session: String,
    pub cognee_dataset_private: String,
}
///Row from the `findings` table
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Findings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub historical_matches: Option<i64>,
    pub severity: String,
    /** Note:
This is a Foreign Key to `tenants.id`.<fk table='tenants' column='id'/>*/
    pub tenant_id: uuid::Uuid,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causal_chain: Option<String>,
    /** Note:
This is a Primary Key.<pk/>*/
    pub id: uuid::Uuid,
    pub vuln_class: String,
    /** Note:
This is a Foreign Key to `audits.id`.<fk table='audits' column='id'/>*/
    pub audit_id: uuid::Uuid,
    pub description: String,
    pub affected_functions: String,
}
///Row from the `contracts` table
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Contracts {
    /** Note:
This is a Primary Key.<pk/>*/
    pub id: uuid::Uuid,
    pub source_hash: String,
    pub uploaded_at: String,
    pub language: String,
    pub source_code: String,
    /** Note:
This is a Foreign Key to `tenants.id`.<fk table='tenants' column='id'/>*/
    pub tenant_id: uuid::Uuid,
    pub name: String,
}
///Row from the `audits` table
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Audits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstract_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_matches: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slither_raw: Option<String>,
    /** Note:
This is a Foreign Key to `tenants.id`.<fk table='tenants' column='id'/>*/
    pub tenant_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /** Note:
This is a Primary Key.<pk/>*/
    pub id: uuid::Uuid,
    /** Note:
This is a Foreign Key to `contracts.id`.<fk table='contracts' column='id'/>*/
    pub contract_id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub status: String,
    pub created_at: String,
}

use postgrest::Postgrest;
impl Tenants {
    /// Check if the current user can SELECT from `#table_name`
    pub async fn can_select_tenants(
        client: &Postgrest,
        user_id: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can INSERT into `#table_name`
    pub async fn can_insert_tenants(
        client: &Postgrest,
        user_id: Option<&str>,
        row: &Self,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can UPDATE rows in `#table_name`
    pub async fn can_update_tenants(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can DELETE from `#table_name`
    pub async fn can_delete_tenants(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
}
impl Findings {
    /// Check if the current user can SELECT from `#table_name`
    pub async fn can_select_findings(
        client: &Postgrest,
        user_id: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can INSERT into `#table_name`
    pub async fn can_insert_findings(
        client: &Postgrest,
        user_id: Option<&str>,
        row: &Self,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can UPDATE rows in `#table_name`
    pub async fn can_update_findings(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can DELETE from `#table_name`
    pub async fn can_delete_findings(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
}
impl Contracts {
    /// Check if the current user can SELECT from `#table_name`
    pub async fn can_select_contracts(
        client: &Postgrest,
        user_id: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can INSERT into `#table_name`
    pub async fn can_insert_contracts(
        client: &Postgrest,
        user_id: Option<&str>,
        row: &Self,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can UPDATE rows in `#table_name`
    pub async fn can_update_contracts(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can DELETE from `#table_name`
    pub async fn can_delete_contracts(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
}
impl Audits {
    /// Check if the current user can SELECT from `#table_name`
    pub async fn can_select_audits(
        client: &Postgrest,
        user_id: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can INSERT into `#table_name`
    pub async fn can_insert_audits(
        client: &Postgrest,
        user_id: Option<&str>,
        row: &Self,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can UPDATE rows in `#table_name`
    pub async fn can_update_audits(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    /// Check if the current user can DELETE from `#table_name`
    pub async fn can_delete_audits(
        client: &Postgrest,
        user_id: Option<&str>,
        row_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
}

impl Tenants {
    pub async fn select_all_tenants(
        client: &postgrest::Postgrest,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("tenants").select("*").execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn select_tenants_eq(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("tenants").select("*").eq(column, value).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_one_tenants(
        client: &postgrest::Postgrest,
        row: &Self,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&row)?;
        let resp = client.from("tenants").insert(body).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_many_tenants(
        client: &postgrest::Postgrest,
        rows: &[Self],
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&rows)?;
        let resp = client.from("tenants").insert(body).execute().await?;
        let text = resp.text().await?;
        let inserted: Vec<Self> = serde_json::from_str(&text)?;
        Ok(inserted)
    }
    pub async fn update_tenants(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
        updates: &serde_json::Value,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(updates)?;
        let resp = client
            .from("tenants")
            .eq(column, value)
            .update(body)
            .execute()
            .await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn delete_tenants(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("tenants").eq(column, value).delete().execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
}
impl Findings {
    pub async fn select_all_findings(
        client: &postgrest::Postgrest,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("findings").select("*").execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn select_findings_eq(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client
            .from("findings")
            .select("*")
            .eq(column, value)
            .execute()
            .await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_one_findings(
        client: &postgrest::Postgrest,
        row: &Self,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&row)?;
        let resp = client.from("findings").insert(body).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_many_findings(
        client: &postgrest::Postgrest,
        rows: &[Self],
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&rows)?;
        let resp = client.from("findings").insert(body).execute().await?;
        let text = resp.text().await?;
        let inserted: Vec<Self> = serde_json::from_str(&text)?;
        Ok(inserted)
    }
    pub async fn update_findings(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
        updates: &serde_json::Value,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(updates)?;
        let resp = client
            .from("findings")
            .eq(column, value)
            .update(body)
            .execute()
            .await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn delete_findings(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("findings").eq(column, value).delete().execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
}
impl Contracts {
    pub async fn select_all_contracts(
        client: &postgrest::Postgrest,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("contracts").select("*").execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn select_contracts_eq(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client
            .from("contracts")
            .select("*")
            .eq(column, value)
            .execute()
            .await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_one_contracts(
        client: &postgrest::Postgrest,
        row: &Self,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&row)?;
        let resp = client.from("contracts").insert(body).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_many_contracts(
        client: &postgrest::Postgrest,
        rows: &[Self],
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&rows)?;
        let resp = client.from("contracts").insert(body).execute().await?;
        let text = resp.text().await?;
        let inserted: Vec<Self> = serde_json::from_str(&text)?;
        Ok(inserted)
    }
    pub async fn update_contracts(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
        updates: &serde_json::Value,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(updates)?;
        let resp = client
            .from("contracts")
            .eq(column, value)
            .update(body)
            .execute()
            .await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn delete_contracts(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("contracts").eq(column, value).delete().execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
}
impl Audits {
    pub async fn select_all_audits(
        client: &postgrest::Postgrest,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("audits").select("*").execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn select_audits_eq(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("audits").select("*").eq(column, value).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_one_audits(
        client: &postgrest::Postgrest,
        row: &Self,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&row)?;
        let resp = client.from("audits").insert(body).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn insert_many_audits(
        client: &postgrest::Postgrest,
        rows: &[Self],
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(&rows)?;
        let resp = client.from("audits").insert(body).execute().await?;
        let text = resp.text().await?;
        let inserted: Vec<Self> = serde_json::from_str(&text)?;
        Ok(inserted)
    }
    pub async fn update_audits(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
        updates: &serde_json::Value,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let body = serde_json::to_string(updates)?;
        let resp = client.from("audits").eq(column, value).update(body).execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
    pub async fn delete_audits(
        client: &postgrest::Postgrest,
        column: &str,
        value: &str,
    ) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
        let resp = client.from("audits").eq(column, value).delete().execute().await?;
        let text = resp.text().await?;
        let rows: Vec<Self> = serde_json::from_str(&text)?;
        Ok(rows)
    }
}
