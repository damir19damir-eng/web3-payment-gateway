package com.payments.gateway.config;

import com.payments.gateway.crypto.SessionRegistry;
import com.payments.gateway.fraud.AnomalyDetector;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class Housekeeping {
    private final SessionRegistry sessions;
    private final AnomalyDetector detector;

    public Housekeeping(SessionRegistry sessions, AnomalyDetector detector) {
        this.sessions = sessions;
        this.detector = detector;
    }

    @Scheduled(fixedRate = 60_000)
    void sweep() {
        sessions.sweep(System.currentTimeMillis());
        detector.evictStale();
    }
}
