import sys
sys.path.insert(0, 'backend')
import asyncio
from app.db.session import async_session_maker
from sqlalchemy import text
from app.services.graph_service import default_graph_service
from app.services.geo_service import default_geo_service
import json

async def inspect():
    async with async_session_maker() as session:
        # 1. Inspect emails
        res = await session.execute(text("SELECT id, subject, sender_address, organization_id, created_at FROM emails"))
        emails = res.fetchall()
        print(f"=== FOUND {len(emails)} EMAILS IN DB ===")
        for e in emails:
            eid, subj, sender, org_id, created = e
            print(f"\nEMAIL: {eid} | Subj: '{subj}' | Sender: '{sender}' | Org: {org_id}")

            # Check email_analysis
            a_res = await session.execute(text("SELECT id, threat_classification, threat_risk_score, summary FROM email_analysis WHERE email_id = :eid"), {"eid": eid})
            analysis = a_res.fetchall()
            print(f"  email_analysis: {analysis}")

            # Check analysis_runs
            ar_res = await session.execute(text("SELECT id, status, analysis_version FROM analysis_runs WHERE email_id = :eid"), {"eid": eid})
            runs = ar_res.fetchall()
            print(f"  analysis_runs: {runs}")

            # Check analysis_findings
            af_res = await session.execute(text("SELECT finding_type, severity, title FROM analysis_findings WHERE email_id = :eid"), {"eid": eid})
            findings = af_res.fetchall()
            print(f"  findings count: {len(findings)} -> {findings[:3]}")

            # Check relay hops
            h_res = await session.execute(text("SELECT sequence_number, source_ip, source_host FROM relay_hops WHERE email_id = :eid"), {"eid": eid})
            hops = h_res.fetchall()
            print(f"  relay hops: {len(hops)} -> {hops}")

            # Check URLs
            u_res = await session.execute(text("SELECT u.normalized_url FROM urls u JOIN email_urls eu ON u.id = eu.url_id WHERE eu.email_id = :eid"), {"eid": eid})
            urls = u_res.fetchall()
            print(f"  urls: {len(urls)} -> {urls[:3]}")

            # Test Graph Service
            try:
                g = await default_graph_service.build_email_investigation_graph(session, eid)
                print(f"  Graph: {g.total_nodes} nodes, {g.total_edges} edges. Node types: {set(n.node_type for n in g.nodes)}")
            except Exception as ge:
                print(f"  Graph ERROR: {ge}")

            # Test Geo Service
            try:
                geo = await default_geo_service.geolocate_email_infrastructure(session, eid)
                print(f"  Geo: {geo['total_hops']} hops, {geo['total_markers']} markers, Tor={geo.get('tor_node_count', 0)}, VPN={geo.get('vpn_node_count', 0)}, Cloud={geo.get('cloud_node_count', 0)}, Personal={geo.get('personal_mail_node_count', 0)}")
            except Exception as geoe:
                print(f"  Geo ERROR: {geoe}")

asyncio.run(inspect())
