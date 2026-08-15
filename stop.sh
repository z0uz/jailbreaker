#!/bin/bash
echo "🛑 Shutting down Jailbreaker Framework..."

# Kill Backend
if [ -f .jailbreaker_api.pid ]; then
    API_PID=$(cat .jailbreaker_api.pid)
    echo "Killing Backend API (PID $API_PID)..."
    kill $API_PID 2>/dev/null || true
    rm -f .jailbreaker_api.pid
else
    echo "Backend API PID not found. (Maybe it's already stopped?)"
fi

# Kill Frontend
if [ -f .jailbreaker_frontend.pid ]; then
    FRONTEND_PID=$(cat .jailbreaker_frontend.pid)
    echo "Killing Frontend Dashboard (PID $FRONTEND_PID)..."
    
    # Next.js npm run dev often spawns child processes (node), so we need to kill the process group or use pkill
    # We will kill the exact node processes running next dev to be safe
    pkill -f "next" 2>/dev/null || true
    
    kill $FRONTEND_PID 2>/dev/null || true
    rm -f .jailbreaker_frontend.pid
else
    echo "Frontend Dashboard PID not found."
fi

echo "✅ All Jailbreaker services stopped successfully."
