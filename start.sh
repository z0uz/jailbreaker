#!/bin/bash
echo "🛡️ Starting Jailbreaker Framework..."

# Ensure logs directory exists
mkdir -p app_logs

# Start FastAPI backend with nohup so it persists
echo "Starting Backend API (port 5001)..."
nohup /home/zouz/miniconda3/bin/python api.py > app_logs/api.log 2>&1 &
API_PID=$!
echo $API_PID > .jailbreaker_api.pid

# Wait a moment for the API to start
sleep 2

# Start Next.js frontend with nohup
echo "Starting Frontend Dashboard (port 3000)..."
cd dashboard
nohup npm run dev > ../app_logs/dashboard.log 2>&1 &
FRONTEND_PID=$!
cd ..
echo $FRONTEND_PID > .jailbreaker_frontend.pid

echo ""
echo "✅ Jailbreaker is now running in the background!"
echo "🌐 Access the dashboard at: http://localhost:3000"
echo "📜 Logs can be found in the 'app_logs/' directory."
echo "🛑 Use ./stop.sh to shut down the framework."
