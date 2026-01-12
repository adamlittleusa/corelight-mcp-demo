import chainlit as cl
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import os

# Configuration to launch the server script as a subprocess
SERVER_PARAMS = StdioServerParameters(
    command="python", 
    args=["server.py"], 
    env=os.environ.copy()
)

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
    else:
        await cl.Message(content="I am an MCP Agent connected to your Corelight SIEM. Try asking:\n\n• **'Find suspicious activity'** — I'll suggest threat hunting tools\n• **'Who are the top talkers?'** — Volume analysis\n• **'Show cleartext credentials'** — Detect exposed passwords\n• **'Find long connections (1 hour)'** — Detect C2 callbacks\n• **'Search for HTTP activity'** — Log search").send()
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
