"""Streamlit web app for netmapper. Run: python3 -m streamlit run app.py"""
import streamlit as st

from netmapper import PORTS, default_subnet, scan_network

st.set_page_config(page_title="netmapper", page_icon="🛰️", layout="wide")
st.title("🛰️ netmapper")
st.caption("Find the devices on your network and see which ports are open.")
st.warning("Only scan networks you own or have permission to scan.")

subnet = st.text_input("Network to scan", value=default_subnet(), help="CIDR format, for example 192.168.1.0/24")

if st.button("Scan", type="primary"):
    try:
        with st.spinner("Scanning, this takes 10 to 30 seconds..."):
            devices = scan_network(subnet)
    except ValueError as err:
        st.error(str(err))
    else:
        high = sum(1 for d in devices if d["risk"] == "high")
        c1, c2 = st.columns(2)
        c1.metric("Devices found", len(devices))
        c2.metric("High-risk ports open", high)
        rows = [{k: d[k] for k in ("ip", "hostname", "mac", "services", "risk")} for d in devices]
        st.dataframe(rows, use_container_width=True)
        for d in devices:
            for port in d["open_ports"]:
                name, risk, why = PORTS[port]
                if risk == "high":
                    st.error(f"{d['ip']} has {name} ({port}) open: {why}")
        # TODO (you): add a Claude explanation per device ("what is this and is it a problem?")
        # TODO (you): show a scan history chart
