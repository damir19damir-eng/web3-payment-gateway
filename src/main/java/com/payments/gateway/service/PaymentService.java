package com.payments.gateway.service;

import com.payments.gateway.dto.PaymentRequest;
import com.payments.gateway.dto.PaymentResponse;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Service
public class PaymentService {

    public Mono<PaymentResponse> processPayment(PaymentRequest request) {
        // Здесь мы добавим логику Redis (идемпотентность), R2DBC и Kafka
        PaymentResponse response = new PaymentResponse(
                request.transactionId(),
                "SUCCESS",
                "Payment processed successfully",
                Instant.now().toString()
        );
        return Mono.just(response);
    }
}