# osint_dorks.py - OSINT & Google Dorking Reconnaissance Module for MHZALY-SOC

import streamlit as st

def render_osint_dorks_module():
    st.markdown("### 🌐 OSINT & Google Dorking Reconnaissance")
    st.markdown("Leverage advanced search operators and Google Dorking payloads for threat intelligence, asset discovery, and vulnerability assessment.")

    # Categories based on modern security intelligence
    dork_categories = {
        "01. Sensitive Files & Credentials": [
            ("Database Dumps & Backups", 'site:target.com filetype:sql OR filetype:bak OR filetype:dump'),
            ("Private Keys & Configs", 'site:target.com ext:pem OR ext:key OR ext:env OR inurl:config'),
            ("Log Files with Passwords", 'site:target.com intext:"password" filetype:log')
        ],
        "02. Cloud Infrastructure & DevOps": [
            ("Public S3 Buckets", 'site:s3.amazonaws.com "target.com"'),
            ("CI/CD Pipelines (Jenkins/GitLab)", 'site:target.com inurl:jenkins OR inurl:gitlab-ci'),
            ("Container Dashboards", 'site:target.com inurl:kubernetes OR inurl:grafana')
        ],
        "03. Modern SaaS & API Endpoints": [
            ("Swagger / API Docs", 'site:target.com inurl:swagger OR inurl:api-docs'),
            ("Admin Portals & SSO", 'site:target.com inurl:admin OR inurl:auth/login'),
            ("GraphQL Endpoints", 'site:target.com inurl:graphql')
        ],
        "04. AI & Machine Learning Infrastructure": [
            ("Exposed OpenAI/API Keys in Notebooks", 'site:target.com filetype:ipynb "OPENAI_API_KEY"'),
            ("Vector Databases & MLFlow", 'site:target.com inurl:mlflow OR inurl:chroma')
        ]
    }

    selected_category = st.selectbox("Select Reconnaissance Category", list(dork_categories.keys()))
    
    st.markdown(f"#### 🔎 Payloads for: {selected_category}")
    target_domain = st.text_input("Enter Target Domain (e.g., target.com):", "example.com")

    st.markdown("---")
    st.markdown("### Generated Dork Queries (Click to Copy & Search):")

    for name, query_template in dork_categories[selected_category]:
        final_query = query_template.replace("target.com", target_domain)
        col1, col2 = st.columns([3, 1])
        with col1:
            st.code(final_query, language="text")
        with col2:
            search_url = f"https://www.google.com/search?q={final_query}"
            st.markdown(f"[🔍 Google Search]({search_url})", unsafe_allow_html=True)

if __name__ == "__main__":
    render_osint_dorks_module()
