#!/bin/bash

# Start FastAPI backend in the background
# IMPORTANT: Use 0.0.0.0 to bind to all network interfaces inside the container
# Use a high non-conflicting port like 8000
echo "Starting FastAPI backend..."
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &

# Wait a moment for FastAPI to start (optional, but good practice)
sleep 5

# Start Streamlit frontend
# Hugging Face Spaces expects the app to be accessible on port 7860
echo "Starting Streamlit frontend..."
streamlit run frontend/app.py --server.port 7860 --server.enableCORS true --server.enableXsrfProtection false