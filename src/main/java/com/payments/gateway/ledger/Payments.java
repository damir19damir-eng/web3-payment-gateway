package com.payments.gateway.ledger;

/** DTO платежа. Суммы — в минорных единицах (центы), без плавающей запятой. */
public final class Payments {
    private Payments() {}

    public record PaymentRequest(String from, String to, long amountMinor, String currency) {}

    public record PaymentResult(String paymentId, String status) {}

    public record PaymentEvent(String paymentId, String src, String dst, long amountMinor, String currency) {}
}
