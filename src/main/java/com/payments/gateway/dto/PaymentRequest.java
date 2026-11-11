package com.payments.gateway.dto;

import java.math.BigDecimal;

public record PaymentRequest(
        String transactionId,
        BigDecimal amount,
        String currency,
        String sourceAccount,
        String targetAccount
) {}