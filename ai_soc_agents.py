import os
import streamlit as st
from crewai import Agent, Task, Crew, Process
from langchain_google_genai import ChatGoogleGenerativeAI

# Streamlit secrets se API key uthana
os.environ["GOOGLE_API_KEY"] = st.secrets["GOOGLE_API_KEY"]

# Gemini Model Setup
llm = ChatGoogleGenerativeAI(model="gemini-1.5-pro")

def run_autonomous_soc_analysis(logs_data):
    
    # 1. AGENTS DEFINITION
    threat_analyzer = Agent(
        role='Senior Threat Hunter & Log Analyzer',
        goal='Analyze system logs to identify cyber attacks, anomalies, and malicious IPs.',
        backstory='Aap ek expert SOC analyst hain. Aapka kaam network logs, web traffic, aur server logs mein chhupe hue attacks ko pakarna hai.',
        verbose=True,
        allow_delegation=False,
        llm=llm
    )

    incident_responder = Agent(
        role='Incident Response Lead',
        goal='Develop an immediate mitigation plan based on the threats found.',
        backstory='Aap ek action-oriented security expert hain. Jab attack pakra jata hai, toh aap block list aur firewall rules update karne ka plan banate hain.',
        verbose=True,
        allow_delegation=False,
        llm=llm
    )

    soc_manager = Agent(
        role='SOC Operations Manager',
        goal='Review the findings and write a final, clean executive report.',
        backstory='Aap MHZALY SOC team ke head hain. Aap technical baaton ko aasan aur professional language mein convert karke final report banate hain.',
        verbose=True,
        allow_delegation=True,
        llm=llm
    )

    # 2. TASKS DEFINITION
    analyze_task = Task(
        description=f'In logs ko ghaur se parhein aur attack identify karein: \n\n{logs_data}',
        expected_output='Detailed list with malicious IPs and attack types.',
        agent=threat_analyzer
    )

    mitigation_task = Task(
        description='Threat Hunter ki report ke mutabiq mitigation plan banayein.',
        expected_output='Step-by-step action plan for firewall.',
        agent=incident_responder
    )

    final_report_task = Task(
        description='Dono reports ko mila kar ek final "MHZALY SOC Incident Report" tayar karein.',
        expected_output='Formatted professional report.',
        agent=soc_manager
    )

    # 3. CREW SETUP
    soc_crew = Crew(
        agents=[threat_analyzer, incident_responder, soc_manager],
        tasks=[analyze_task, mitigation_task, final_report_task],
        process=Process.sequential 
    )

    result = soc_crew.kickoff()
    return result
