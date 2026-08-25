# osint_dorks.py - Advanced OSINT & Google Dorking Reconnaissance Module for MHZALY-SOC

import streamlit as st
import pandas as pd
import urllib.parse

def render_osint_dorks_module():
    st.title("🌐 OSINT & Google Dorking Reconnaissance")
    st.markdown("Automate open-source intelligence footprinting and defensive reconnaissance queries for target assets.")

    dork_categories = {
        "01. Sensitive Files & Credentials": [
            ("Database Dumps & Backups", 'site:target.com (filetype:sql OR filetype:bak OR filetype:dump)', "Critical"),
            ("Private Keys & Environment Configs", 'site:target.com (ext:pem OR ext:key OR ext:env OR inurl:config)', "Critical"),
            ("Exposed Log Files with Passwords", 'site:target.com intext:"password" filetype:log', "High")
        ],
        "02. WordPress Security & Reconnaissance": [
            ("Exposed WP-Config & Backups", 'site:target.com (inurl:wp-config.php OR inurl:wp-config.bak)', "Critical"),
            ("Vulnerable / Exposed Plugins", 'site:target.com inurl:/wp-content/plugins/', "High"),
            ("Uploaded Media & File Dorks", 'site:target.com inurl:/wp-content/uploads/', "Medium"),
            ("WordPress Author Enumeration", 'site:target.com/?author=', "Medium"),
            ("Exposed XML-RPC Endpoints", 'site:target.com inurl:xmlrpc.php', "High")
        ],
        "03. Cloud Infrastructure & DevOps": [
            ("Public S3 Buckets", 'site:s3.amazonaws.com "target.com"', "High"),
            ("CI/CD Automation Pipelines", 'site:target.com (inurl:jenkins OR inurl:gitlab-ci)', "Medium"),
            ("Container Dashboards & Telemetry", 'site:target.com (inurl:kubernetes OR inurl:grafana)', "High")
        ],
        "04. Modern SaaS & API Endpoints": [
            ("Swagger / API Documentation", 'site:target.com (inurl:swagger OR inurl:api-docs)', "Medium"),
            ("Admin Portals & SSO Endpoints", 'site:target.com (inurl:admin OR inurl:auth/login)', "Medium"),
            ("GraphQL Endpoints", 'site:target.com inurl:graphql', "Low")
        ],
        "05. AI & ML Infrastructure": [
            ("Exposed OpenAI/API Tokens in Notebooks", 'site:target.com filetype:ipynb "OPENAI_API_KEY"', "Critical"),
            ("Vector Databases & MLflow Tracking", 'site:target.com (inurl:mlflow OR inurl:chroma)', "Medium")
        ]
    }

    target_domain = st.text_input("Enter Target Domain (e.g., example.com):", "example.com")
    clean_domain = target_domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0]

    col1, col2 = st.columns([1, 1])
    with col1:
        selected_category = st.selectbox("Select Reconnaissance Category", list(dork_categories.keys()))
    with col2:
        st.metric("Target Asset", clean_domain, "Domain Active")

    st.markdown("---")
    st.markdown(f"### 🎯 Active Query Set: {selected_category}")

    recon_records = []
    for name, query_template, risk in dork_categories[selected_category]:
        final_query = query_template.replace("target.com", clean_domain)
        encoded_query = urllib.parse.quote(final_query)
        search_url = f"https://www.google.com/search?q={encoded_query}"
        
        recon_records.append({
            "Vector Objective": name,
            "Risk Rating": risk,
            "Google Dork Payload": final_query,
            "Launch URL": search_url
        })

    df_recon = pd.DataFrame(recon_records)
    st.dataframe(df_recon[["Vector Objective", "Risk Rating", "Google Dork Payload"]], use_container_width=True, hide_index=True)

    st.markdown("### 🚀 Live Search Actions")
    for item in recon_records:
        st.markdown(f"- **{item['Vector Objective']}** (`{item['Risk Rating']}`): [Launch Query on Search Engine ↗]({item['Launch URL']})")

if __name__ == "__main__":
    render_osint_dorks_module()
