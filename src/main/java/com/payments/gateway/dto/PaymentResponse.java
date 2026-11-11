package com.payments.gateway.dto;

public record PaymentResponse(
        String transactionId,
        String status,
        String message,
        String timestamp
) {}