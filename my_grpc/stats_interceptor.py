# my_grpc/stats_interceptor.py

import grpc
import threading

class ByteCountingInterceptor(grpc.UnaryUnaryClientInterceptor):
    """
    Intercepts unary-unary sync gRPC calls to measure request/response protobuf sizes.
    We'll store counters as class-level variables so we can safely reference them
    even inside nested functions.
    """

    total_bytes_sent = 0
    total_bytes_received = 0
    _lock = threading.Lock()

    @classmethod
    def reset_counters(cls):
        with cls._lock:
            cls.total_bytes_sent = 0
            cls.total_bytes_received = 0

    @classmethod
    def get_counters(cls):
        with cls._lock:
            return cls.total_bytes_sent, cls.total_bytes_received

    def intercept_unary_unary(self, continuation, client_call_details, request):
        # 1) Measure outgoing request size
        serialized_request = request.SerializeToString()
        with ByteCountingInterceptor._lock:
            ByteCountingInterceptor.total_bytes_sent += len(serialized_request)

        # 2) Invoke the RPC. For sync calls, this typically returns a _UnaryOutcome object
        #    that has .result().
        outcome = continuation(client_call_details, request)

        # If for some reason it lacks .result(), we can't measure the response size:
        if not hasattr(outcome, 'result'):
            return outcome

        real_result = outcome.result

        def wrapped_result(*args, **kwargs):
            # 3) When the caller eventually calls outcome.result(), we get the actual response
            response = real_result(*args, **kwargs)
            # Measure that response's size
            serialized_response = response.SerializeToString()
            with ByteCountingInterceptor._lock:
                ByteCountingInterceptor.total_bytes_received += len(serialized_response)
            return response

        outcome.result = wrapped_result
        return outcome
