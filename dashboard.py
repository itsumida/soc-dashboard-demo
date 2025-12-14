import pandas as pd
import streamlit as st
import plotly.express as px

st.set_page_config(page_title="SOC Demo", layout="wide")

@st.cache_data
def load_data():
    df = pd.read_csv("insights_events.csv", parse_dates=["timestamp"])
    df["date"] = df["timestamp"].dt.date
    return df

def calculate_risk_score(event, country, timestamp):
    """Calculate risk score based on event type, location, and time patterns"""
    base_scores = {
        "root_detected": 30,
        "hooking_attempt": 25,
        "emulator_detected": 20,
        "debugger_attached": 15
    }
    
    # Base score from event type
    score = base_scores.get(event, 10)
    
    # Context-based adjustments (mock logic)
    high_risk_countries = ["USA", "Germany"]  # Example: countries with more fraud
    if country in high_risk_countries:
        score += 10
    
    # Time-based patterns (mock: higher risk during off-hours)
    hour = timestamp.hour
    if hour < 6 or hour > 22:  # Off-hours
        score += 5
    
    # Cap at 100
    return min(score, 100)

def get_risk_level(score):
    """Convert numeric score to risk level"""
    if score >= 76:
        return "Critical"
    elif score >= 51:
        return "High"
    elif score >= 26:
        return "Medium"
    else:
        return "Low"

df = load_data()

# Calculate risk scores for all events
df["risk_score"] = df.apply(lambda row: calculate_risk_score(row["event"], row["country"], row["timestamp"]), axis=1)
df["risk_level"] = df["risk_score"].apply(get_risk_level)

st.title("MOCK SOC Dashboard")

with st.expander("What is this dashboard?", expanded=True):
    st.markdown(
        """
        It summarizes events, trends, and simple alert rules.

        Events shown:
        - `root_detected`: Device appears rooted/jailbroken
        - `emulator_detected`: App is running in an emulator/sandbox
        - `hooking_attempt`: Potential runtime hooking or instrumentation (e.g., Frida)
        - `debugger_attached`: Debugger detected during runtime

        Risk scoring considers:
        - Event type (base score)
        - Geographic context (high-risk countries get +10)
        - Time patterns (off-hours get +5)
        - Risk levels: Low (0-25), Medium (26-50), High (51-75), Critical (76-100)
        """
    )

# --- Sidebar: global filters ---
with st.sidebar:
    st.header("Filters")
    min_date = df["date"].min()
    max_date = df["date"].max()
    date_range = st.date_input("Date range", value=(min_date, max_date))

    event_sel = st.multiselect("Event type", sorted(df["event"].unique()))
    country_sel = st.multiselect("Country", sorted(df["country"].unique()))
    risk_sel = st.multiselect("Risk level", sorted(df["risk_level"].unique()))

    # Optional per-app filters (shown only if columns exist)
    optional_filters = {}
    for col, label in [
        ("package", "App package"),
        ("app_version", "App version"),
        ("build_number", "Build number"),
        ("environment", "Environment"),
        ("session_id", "Session ID"),
    ]:
        if col in df.columns:
            vals = sorted([v for v in df[col].dropna().unique()])
            if vals:
                optional_filters[col] = st.multiselect(label, vals)

# Apply global filters
filtered = df.copy()
if isinstance(date_range, tuple) and len(date_range) == 2:
    start, end = date_range
    filtered = filtered[(filtered["date"] >= start) & (filtered["date"] <= end)]
if event_sel:
    filtered = filtered[filtered["event"].isin(event_sel)]
if country_sel:
    filtered = filtered[filtered["country"].isin(country_sel)]
if risk_sel:
    filtered = filtered[filtered["risk_level"].isin(risk_sel)]
# Apply optional filters if present
for col, selected in (optional_filters.items() if 'optional_filters' in locals() else []):
    if selected:
        filtered = filtered[filtered[col].isin(selected)]

# KPI row (from filtered)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", f"{len(filtered):,}")
col2.metric("Critical Risk", f"{(filtered['risk_level']=='Critical').sum():,}")
col3.metric("Unique Devices", f"{filtered['device'].nunique():,}")
col3.metric("Avg Risk Score", f"{filtered['risk_score'].mean():.1f}")
col4.metric("Unique Devices", f"{filtered['device'].nunique():,}")

# Charts
c1, c2 = st.columns(2)
with c1:
    st.subheader("Top Attack Types")
    vc_event = filtered["event"].value_counts().sort_values(ascending=False)
    st.bar_chart(vc_event)

with c2:
    st.subheader("Events by Country")
    vc_country = filtered["country"].value_counts().sort_values(ascending=False)
    st.bar_chart(vc_country)

# Risk distribution chart
st.subheader("Risk Distribution")
risk_dist = filtered["risk_level"].value_counts()
st.bar_chart(risk_dist)

# Choropleth map by country (Plotly)
if not filtered.empty and "country" in filtered.columns:
    st.subheader("Geo Distribution")
    geo_counts = filtered.groupby("country").size().reset_index(name="events")
    fig = px.choropleth(
        geo_counts,
        locations="country",
        locationmode="country names",
        color="events",
        color_continuous_scale="YlOrRd",
        labels={"events": "Events"},
    )
    fig.update_layout(margin=dict(l=0, r=0, t=0, b=0))
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Threats Over Time")
# Group by date and event for a multi-series line
if not filtered.empty:
    ts = (
        filtered.groupby(["date", "event"]).size().unstack(fill_value=0).sort_index()
    )
    st.line_chart(ts)
else:
    st.info("No data for the selected filters.")

st.divider()

# Session drill-down by device
st.subheader("Session Drill-down by Device")
if not filtered.empty:
    device_options = sorted(filtered["device"].dropna().unique())
    sel_device = st.selectbox("Choose a device", options=device_options)
    dev_df = filtered[filtered["device"] == sel_device].sort_values("timestamp")
    st.caption(f"{len(dev_df)} events for: {sel_device}")
    if not dev_df.empty:
        # Timeline scatter by event category (no severity colors)
        fig_dev = px.scatter(
            dev_df,
            x="timestamp",
            y="event",
            color="risk_score",
            hover_data=["country", "device", "risk_level"],
            title=None,
            color_continuous_scale="RdYlBu_r",
        )
        fig_dev.update_traces(marker=dict(size=10, opacity=0.8))
        fig_dev.update_layout(margin=dict(l=0, r=0, t=0, b=0), yaxis_title="Event")
        st.plotly_chart(fig_dev, use_container_width=True)
        st.dataframe(dev_df, use_container_width=True)
    else:
        st.info("No events for the selected device.")
else:
    st.info("No data to drill down.")

# Raw data download at the end
st.divider()
st.subheader("Export Data")
csv = filtered.sort_values("timestamp").to_csv(index=False).encode("utf-8")
st.download_button(
    label="📥 Download filtered data as CSV",
    data=csv,
    file_name="filtered_events.csv",
    mime="text/csv",
    use_container_width=True,
)

# --- Alert rule (demo) ---
st.divider()
st.subheader("Alert Rules (demo)")

window_min = st.slider("Rolling window (minutes)", 1, 30, 5)
threshold = st.number_input("Threshold (events in window)", min_value=1, value=10)
scope = st.radio("Scope", ["Per country", "Per device"], horizontal=True)

# Use filtered data but focus on emulator events as before
base = filtered[filtered["event"] == "emulator_detected"].copy()
if base.empty:
    st.info("No emulator_detected events in the current filtered dataset.")
else:
    base = base.sort_values("timestamp").set_index("timestamp")
    group_key = "country" if scope == "Per country" else "device"

    alerts = []
    for key, g in base.groupby(group_key):
        counts = g["event"].rolling(f"{window_min}min").count()
        hits = counts[counts >= threshold]
        for t in hits.index:
            alerts.append({
                "time": t,
                "scope": group_key,
                group_key: key,
                "rule": f"Emulator≥{threshold} in {window_min} min",
            })
    if alerts:
        st.error(f"ALERTS TRIGGERED: {len(alerts)}")
        st.dataframe(pd.DataFrame(alerts).sort_values("time"), use_container_width=True)
    else:
        st.success("No alerts triggered with current rule.")
