import streamlit as st
import requests
from datetime import datetime

# Set page config
st.set_page_config(
    page_title="URL Safety Analyzer",
    page_icon="🔍",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #4CAF50;
        color: white;
        padding: 0.5rem 1rem;
        border: none;
        border-radius: 4px;
        font-size: 1.1rem;
    }
    .stButton>button:hover {
        background-color: #45a049;
    }
    .result-box {
        padding: 1.5rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: #333;
    }
    .result-box h2 {
        font-size: 1.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .safe {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
    }
    .safe h2 {
        color: #0f5132;  /* Darker green for safe status */
    }
    .suspicious {
        background-color: #fff3cd;
        border: 1px solid #ffeeba;
    }
    .suspicious h2 {
        color: #664d03;  /* Darker yellow/brown for suspicious status */
    }
    .dangerous {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
    }
    .dangerous h2 {
        color: #842029;  /* Darker red for dangerous status */
    }
    .metric-box {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 4px;
        margin: 0.5rem 0;
        color: #212529;
    }
    .metric-box strong {
        color: #000;
    }
    .metric-box p {
        color: #212529;
        margin: 0.5rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

# YOUR BACKEND RENDER URL
API_URL = "https://url-detection-ylju.onrender.com/predict"

# Header
st.title("🔍 URL Safety Analyzer")
st.markdown("""
    This tool helps you analyze URLs for potential security risks. 
    Enter a URL below to check if it's safe, suspicious, or potentially dangerous.
""")

# Input section
with st.container():
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    with col2:
        analyze_button = st.button("Analyze URL")

# Results section
if analyze_button:
    if not url:
        st.warning("⚠️ Please enter a URL to analyze.")
    else:
        with st.spinner("Analyzing URL..."):
            try:
                response = requests.post(API_URL, json={"url": url})
                if response.status_code == 200:
                    data = response.json()
                    result = data["result"]
                    confidence = data["confidence"]
                    is_malicious = data["is_malicious"]
                    details = data["details"]

                    # Determine status based on confidence and malicious flag
                    if is_malicious:
                        if confidence >= 95:
                            status = "🚨 Dangerous"
                            status_class = "dangerous"
                        else:
                            status = "⚠️ Suspicious"
                            status_class = "suspicious"
                    else:
                        if confidence >= 95:
                            status = "✅ Safe"
                            status_class = "safe"
                        else:
                            status = "⚠️ Suspicious"
                            status_class = "suspicious"

                    # Display results
                    st.markdown(f"""
                        <div class="result-box {status_class}">
                            <h2 style="margin: 0;">{status}</h2>
                            <p style="margin: 0.5rem 0;">Model Confidence: {confidence}%</p>
                            <p style="margin: 0.5rem 0; font-size: 0.9rem; color: #666;">
                                {f"High confidence ({confidence}%) - We can trust this assessment" if confidence >= 95 
                                else f"Low confidence ({confidence}%) - Exercise caution with this assessment"}
                            </p>
                        </div>
                    """, unsafe_allow_html=True)

                    # Detailed analysis
                    st.subheader("📊 Detailed Analysis")
                    
                    # Create columns for metrics
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("### 🔍 URL Analysis")
                        st.markdown(f"""
                            <div class="metric-box">
                                <strong>Domain Age:</strong> {details.get('domain_age', 'N/A')}<br>
                                <strong>SSL Certificate:</strong> {'✅ Valid' if details.get('has_ssl', False) else '❌ Invalid'}<br>
                                <strong>Domain Reputation:</strong> {details.get('domain_reputation', 'N/A')}
                            </div>
                        """, unsafe_allow_html=True)

                    with col2:
                        st.markdown("### 🛡️ Security Metrics")
                        st.markdown(f"""
                            <div class="metric-box">
                                <strong>IP Reputation:</strong> {details.get('ip_reputation', 'N/A')}<br>
                                <strong>Known Malware:</strong> {'❌ Detected' if details.get('known_malware', False) else '✅ Clean'}<br>
                                <strong>Phishing Risk:</strong> {details.get('phishing_risk', 'N/A')}
                            </div>
                        """, unsafe_allow_html=True)

                    # Additional information
                    st.markdown("### ℹ️ Additional Information")
                    st.markdown(f"""
                        <div class="metric-box">
                            <strong>Analysis Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                            <strong>URL Type:</strong> {details.get('url_type', 'N/A')}<br>
                            <strong>Content Analysis:</strong> {details.get('content_analysis', 'N/A')}
                        </div>
                    """, unsafe_allow_html=True)

                    # Recommendations
                    st.markdown("### 💡 Recommendations")
                    if status == "🚨 Dangerous":
                        st.error("""
                            ⚠️ This URL appears to be dangerous. We recommend:
                            - Do not visit this URL
                            - Do not enter any personal information
                            - Report this URL to your security team
                        """)
                    elif status == "⚠️ Suspicious":
                        st.warning("""
                            ⚠️ This URL shows suspicious characteristics. We recommend:
                            - Exercise caution when visiting
                            - Verify the source through other means
                            - Don't enter sensitive information
                        """)
                    else:
                        st.success("""
                            ✅ This URL appears to be safe. However, always:
                            - Keep your security software updated
                            - Be cautious with personal information
                            - Verify the website's legitimacy
                        """)

                else:
                    st.error(f"❌ API Error: {response.status_code} - {response.text}")
            except Exception as e:
                st.error(f"❌ Error analyzing URL: {str(e)}")

# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>🔒 This tool uses advanced algorithms to analyze URLs for potential security risks.</p>
        <p>Last updated: {}</p>
    </div>
""".format(datetime.now().strftime('%Y-%m-%d')), unsafe_allow_html=True)