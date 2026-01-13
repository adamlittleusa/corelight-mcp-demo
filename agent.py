import chainlit as cl
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import os
import json
import asyncio

# Optional LLM fallback for routing/answers using Google Gemini
try:
    import google.generativeai as genai
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if gemini_api_key:
        genai.configure(api_key=gemini_api_key)
        model_name = os.environ.get("GEMINI_MODEL", "models/gemini-2.5-flash")
        gemini_model = genai.GenerativeModel(model_name)
    else:
        gemini_model = None
except ImportError:  # pragma: no cover
    gemini_model = None

# Configuration to launch the server script as a subprocess
SERVER_PARAMS = StdioServerParameters(
    command="python", 
    args=["server.py"], 
    env=os.environ.copy()
)


async def llm_route(user_text: str):
    """Use an LLM to decide a tool or answer when no keyword matched."""
    # Check API Key first
    if not os.environ.get("GEMINI_API_KEY"):
        return {
            "mode": "answer", 
            "text": "✨ *Gemini is currently unavailable (API Key missing), but I can still help!* \n\n"
                   "I'm optimized for these Corelight tools:\n"
                   "• **top talkers** (Volume analysis)\n"
                   "• **search** (General log hunting)\n"
                   "• **dns** (Beaconing detection)\n"
                   "• **long connections** (C2 detection)\n"
                   "• **credentials** (Cleartext password audit)"
        }
    
    try:
        # Use the full model path with the latest stable model
        model = genai.GenerativeModel('models/gemini-2.5-flash')
        
        system_prompt = (
            "You are a Senior Corelight SOC Analyst. The user asked: '{user_text}'. "
            "Choose ONE: (a) call_tool: {\"tool\": <name>, \"args\": {...}} from "
            "[search_zeek_logs, get_top_talkers, find_long_connections, audit_cleartext_creds, get_dns_summary] "
            "or (b) answer: <short helpful text>. Keep responses concise."
        )
        
        prompt = f"{system_prompt}\n\nUser request: {user_text}"
        
        # Generate content with error handling
        response = await asyncio.to_thread(
            model.generate_content,
            prompt
        )
        
        content = response.text if response.text else ""
        
        # Try to parse JSON if present
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        
        # Fallback: treat as answer text
        return {"mode": "answer", "text": content or "I can help search logs, find long connections, DNS beaconing, credentials, or top talkers."}
        
    except Exception as e:
        # If Gemini fails, don't crash—just give the user a 'manual' hint
        print(f"DEBUG: Gemini Error: {e}")
        return {
            "mode": "answer",
            "text": "✨ *Gemini is currently unavailable, but I can still help!* \n\n"
                   "I'm optimized for these Corelight tools:\n"
                   "• **top talkers** (Volume analysis)\n"
                   "• **search** (General log hunting)\n"
                   "• **dns** (Beaconing detection)\n"
                   "• **long connections** (C2 detection)\n"
                   "• **credentials** (Cleartext password audit)"
        }

@cl.on_chat_start
async def start():
    # 1. Initialize the UI
    await cl.Message(content="**Initializing MCP Connection to Corelight SIEM...**").send()
    
    # 2. Test Connection & Discover Tools
    try:
        async with stdio_client(SERVER_PARAMS) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = [t.name for t in tools.tools]
                
                await cl.Message(
                    content=f"✅ **MCP Agent Online.**\n\nI have connected to the `Corelight-SIEM-Gateway`.\nI have access to the following tools:\n- `" + "`\n- `".join(tool_names) + "`"
                ).send()
    except Exception as e:
        await cl.Message(content=f"❌ **Connection Failed:** {e}").send()

@cl.on_message
async def main(message: cl.Message):
    user_input = message.content.lower()
    
    # NOTE: In a production 'Agent', an LLM (GPT-4) would decide which tool to call.
    # For this demo reliability, we use keyword routing to TRIGGER the tool call.
    # This demonstrates the ARCHITECTURE without needing an API Key.
    
    tool_to_call = None
    tool_args = {}
    narrative = ""

    # Menu command - show all available tools
    if "menu" in user_input or "help" in user_input or "tools" in user_input:
        try:
            async with stdio_client(SERVER_PARAMS) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    
                    menu_text = "📋 **Available MCP Tools**\n\n"
                    menu_text += "I have access to the following tools:\n\n"
                    
                    for tool in tools.tools:
                        menu_text += f"**`{tool.name}`**\n"
                        if tool.description:
                            menu_text += f"  └─ {tool.description}\n"
                        menu_text += "\n"
                    
                    menu_text += "\n**Quick Commands:**\n"
                    menu_text += "• `top talkers` - Volume analysis\n"
                    menu_text += "• `weird events` - Protocol anomalies\n"
                    menu_text += "• `long connections` - C2 detection\n"
                    menu_text += "• `cleartext credentials` - Password exposure\n"
                    menu_text += "• `dns summary` - DNS beaconing\n"
                    menu_text += "• `smart pcap triggers` - Suspicious events\n"
                    menu_text += "• `search <query>` - Log search\n"
                    menu_text += "• `menu` - Show this menu\n"
                    
                    await cl.Message(content=menu_text).send()
                    return
        except Exception as e:
            await cl.Message(content=f"❌ Could not retrieve tool menu: {e}").send()
            return

    if "top talker" in user_input or "volume" in user_input:
        narrative = "🤖 *Reasoning: User asked for volume metrics. Delegating to `get_top_talkers` tool via MCP...*"
        tool_to_call = "get_top_talkers"
        tool_args = {}
        
    elif "suspicious" in user_input or "anomal" in user_input or "threat" in user_input or "attack" in user_input:
        # Smart routing for threat hunting - suggest specific tools instead of generic search
        response_text = """🤖 **Threat Hunting Assistant**

I can help you investigate suspicious activity! I have specialized tools for different types of threats:

1. **🔐 Cleartext Credentials** — Detect FTP/HTTP passwords exposed in network traffic
   *Try: "Show me cleartext credentials" or "Audit for passwords"*

2. **🔗 Long-Lived Connections** — Find C2 callbacks & persistent connections (>1hr)
   *Try: "Find long connections" or "Show me connections lasting over 1 hour"*

3. **📊 Top Talkers** — Identify high-volume sources (data exfil, scanning)
   *Try: "Who are the top talkers?"*

4. **🔍 Log Search** — Search for specific protocols, IPs, or patterns
   *Try: "Search for DNS queries to suspicious domains"*

**What would you like to investigate?**"""
        
        await cl.Message(content=response_text).send()
        return
        
    elif "search" in user_input or "investigate" in user_input:
        narrative = "🤖 *Reasoning: User asked for investigation. Delegating to `search_zeek_logs` tool via MCP...*"
        tool_to_call = "search_zeek_logs"
        # Try to extract search intent from user input
        import re
        # Look for specific patterns or domains
        if "dns" in user_input:
            tool_args = {"query_string": "event_type:dns OR proto:dns"}
        elif "http" in user_input or "web" in user_input:
            tool_args = {"query_string": "event_type:http OR proto:http OR method:*"}
        elif "ip" in user_input or "address" in user_input:
            # Try to find IP in input
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', user_input)
            if ip_match:
                tool_args = {"query_string": f"id.orig_h:{ip_match.group(1)} OR id.resp_h:{ip_match.group(1)}"}
            else:
                tool_args = {"query_string": "*"}
        else:
            tool_args = {"query_string": "*"}
        
    elif "long" in user_input or "long-lived" in user_input or "long lived" in user_input or "duration" in user_input or "long connections" in user_input or "c2" in user_input or "command and control" in user_input:
        narrative = "🤖 *Reasoning: User asked for long-lived connections. Delegating to `find_long_connections` tool via MCP...*"
        tool_to_call = "find_long_connections"
        # Allow user to specify seconds like '1 hour' or '3600s' - naive parse
        tool_args = {}
        # simple pattern: look for numbers in input
        import re
        m = re.search(r"(\d+)\s*(s|sec|secs|seconds)?", user_input)
        if m:
            try:
                tool_args['threshold_seconds'] = int(m.group(1))
            except Exception:
                pass
        else:
            # check for hours/minutes
            m2 = re.search(r"(\d+)\s*(h|hr|hours)", user_input)
            if m2:
                try:
                    tool_args['threshold_seconds'] = int(m2.group(1)) * 3600
                except Exception:
                    pass
        
    elif "credential" in user_input or "password" in user_input or "cleartext" in user_input or "ftp" in user_input or "telnet" in user_input or "basic auth" in user_input:
        narrative = "🤖 *Reasoning: User asked for credentials. Delegating to `audit_cleartext_creds` tool via MCP...*"
        tool_to_call = "audit_cleartext_creds"
        tool_args = {}
    
    elif "dns" in user_input or "domain" in user_input or "beacon" in user_input or "dga" in user_input:
        narrative = "🤖 *Reasoning: User asked for DNS beaconing summary. Delegating to `get_dns_summary` tool via MCP...*"
        tool_to_call = "get_dns_summary"
        tool_args = {}
    
    elif "smart pcap" in user_input or "pcap trigger" in user_input or "alert" in user_input or "trigger" in user_input:
        narrative = "🤖 *Reasoning: User asked for Smart PCAP triggers. Delegating to `find_smart_pcap_triggers` tool via MCP...*"
        tool_to_call = "find_smart_pcap_triggers"
        tool_args = {}
    
    elif "extract" in user_input or "packet" in user_input:
        # Look for UID in the input
        import re
        uid_match = re.search(r'[A-Za-z0-9]{14,18}', user_input)
        if uid_match:
            uid = uid_match.group(0)
            narrative = f"🤖 *Reasoning: User wants to extract packets for UID {uid}. Delegating to `extract_packets` tool via MCP...*"
            tool_to_call = "extract_packets"
            tool_args = {"uid": uid}
        else:
            await cl.Message(content="To extract packets, please provide a connection UID.\n\nExample: 'extract packets for C1a2b3c4d5e6f7'").send()
            return
    
    elif "connection detail" in user_input or "uid" in user_input.lower():
        # Look for UID in the input
        import re
        uid_match = re.search(r'[A-Za-z0-9]{14,18}', user_input)
        if uid_match:
            uid = uid_match.group(0)
            narrative = f"🤖 *Reasoning: User wants connection details for UID {uid}. Delegating to `get_connection_details` tool via MCP...*"
            tool_to_call = "get_connection_details"
            tool_args = {"uid": uid}
        else:
            await cl.Message(content="To get connection details, please provide a connection UID.\n\nExample: 'show details for C1a2b3c4d5e6f7'").send()
            return
    
    elif "weird" in user_input or "anomal" in user_input or "protocol" in user_input:
        narrative = "🤖 *Reasoning: User asked for weird events. Delegating to `get_weird_events` tool via MCP...*"
        tool_to_call = "get_weird_events"
        tool_args = {}
    
    else:
        # LLM fallback: decide on a tool or give an answer
        await cl.Message(content="🤖 *No direct keyword matched; consulting LLM for best action...*").send()
        decision = await llm_route(message.content)
        if decision.get("mode") == "call_tool" and decision.get("tool"):
            tool_to_call = decision.get("tool")
            tool_args = decision.get("args", {})
            narrative = f"🤖 *LLM chose tool `{tool_to_call}` for your request.*"
        else:
            answer = decision.get("text", "I can help with top talkers, long connections, DNS beaconing, credentials, or log search.")
            await cl.Message(content=answer).send()
            return

    # Execute the Tool Call via MCP Protocol
    await cl.Message(content=narrative).send()
    
    try:
        async with stdio_client(SERVER_PARAMS) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                # The actual "Agent" act: Calling the remote tool
                result = await session.call_tool(tool_to_call, arguments=tool_args)
                
                # Extract text content from result
                if result.content and hasattr(result.content[0], 'text'):
                    final_text = result.content[0].text
                else:
                    final_text = str(result)

                await cl.Message(content=f"**Tool Output:**\n\n```\n{final_text}\n```").send()
                
    except Exception as e:
        await cl.Message(content=f"❌ Tool Execution Failed: {e}").send()
