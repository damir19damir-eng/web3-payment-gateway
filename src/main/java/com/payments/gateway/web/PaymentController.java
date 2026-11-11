package com.payments.gateway.web;

import com.payments.gateway.dto.PaymentRequest;
import com.payments.gateway.dto.PaymentResponse;
import com.payments.gateway.service.PaymentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/payments")
public class PaymentController {

    private final PaymentService paymentService;

    public PaymentController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @PostMapping("/process")
    public Mono<ResponseEntity<PaymentResponse>> processPayment(@RequestBody PaymentRequest request) {
        String txId = (request.transactionId() != null && !request.transactionId().isBlank())
                ? request.transactionId()
                : UUID.randomUUID().toString();

        PaymentResponse response = new PaymentResponse(
                txId,
                "SUCCESS",
                "Payment processed successfully",
                Instant.now().toString()
        );

        return Mono.just(ResponseEntity.ok(response));
    }
}