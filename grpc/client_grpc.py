#!/usr/bin/env python3
import argparse
import grpc
import chat_pb2
import chat_pb2_grpc

def run():
    parser = argparse.ArgumentParser(description="gRPC Chat Client")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=50051, help="Server port (default: 50051)")
    args = parser.parse_args()

    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = chat_pb2_grpc.ChatServiceStub(channel)
    
    # For demonstration, send a sample command. For example, to show the database.
    command_text = "SHOW_DB"
    request = chat_pb2.CommandRequest(version="1.0", command=command_text)
    response = stub.ProcessCommand(request)
    
    print("Response from server:")
    print(f"Version: {response.version}")
    print(f"Status: {response.status}")
    print(f"Message: {response.message}")

if __name__ == "__main__":
    run()
