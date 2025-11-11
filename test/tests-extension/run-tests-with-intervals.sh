#!/bin/bash

export KUBECONFIG=/home/kewang/github-go/openshift/kubeconfig

echo "=========================================="
echo "Test Suite Execution with 10-min Intervals"
echo "=========================================="
echo ""

# Function to wait with countdown
wait_with_countdown() {
    local minutes=$1
    local seconds=$((minutes * 60))
    echo ""
    echo "⏳ Waiting ${minutes} minutes for cluster to stabilize..."
    for ((i=seconds; i>0; i--)); do
        printf "\r   Time remaining: %02d:%02d " $((i/60)) $((i%60))
        sleep 1
    done
    printf "\r   Time remaining: 00:00 ✓\n"
    echo ""
}

# Suite 1: Webhook Injection (RUN FIRST - needs fresh cluster)
echo "=========================================="
echo "Suite 1: Webhook Injection Test"
echo "Started: $(date)"
echo "=========================================="
./bin/service-ca-operator-tests-ext run-test "Service CA Operator Webhook Injection should inject CA bundle into all webhook types"
WEBHOOK_RESULT=$?
echo "Result: Exit code $WEBHOOK_RESULT"
echo "Finished: $(date)"

wait_with_countdown 10

# Suite 2: CA Rotation Tests (serial tests)
echo "=========================================="
echo "Suite 2: CA Rotation Tests"
echo "Started: $(date)"
echo "=========================================="
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should handle time-based CA rotation"
ROTATION1_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should handle forced CA rotation"
ROTATION2_RESULT=$?
ROTATION_RESULT=$((ROTATION1_RESULT + ROTATION2_RESULT))
echo "Result: Exit code $ROTATION_RESULT"
echo "Finished: $(date)"

wait_with_countdown 10

# Suite 3: Serving Cert Tests
echo "=========================================="
echo "Suite 3: Serving Cert Tests"
echo "Started: $(date)"
echo "=========================================="
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should create a serving cert secret for services with the serving-cert annotation"
SERVING1_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should recreate a serving cert secret when the secret is deleted"
SERVING2_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should regenerate serving cert secret when TLS cert is modified"
SERVING3_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should remove extra data from serving cert secret"
SERVING4_RESULT=$?
SERVING_RESULT=$((SERVING1_RESULT + SERVING2_RESULT + SERVING3_RESULT + SERVING4_RESULT))
echo "Result: Exit code $SERVING_RESULT"
echo "Finished: $(date)"

wait_with_countdown 10

# Suite 4: CA Bundle Injection Tests
echo "=========================================="
echo "Suite 4: CA Bundle Injection Tests"
echo "Started: $(date)"
echo "=========================================="
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should inject a CA bundle into an annotated configmap"
INJECTION1_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should update CA bundle injection configmap when modified"
INJECTION2_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should handle vulnerable legacy CA bundle injection configmap"
INJECTION3_RESULT=$?
INJECTION_RESULT=$((INJECTION1_RESULT + INJECTION2_RESULT + INJECTION3_RESULT))
echo "Result: Exit code $INJECTION_RESULT"
echo "Finished: $(date)"

wait_with_countdown 10

# Suite 5: Metrics and Misc Tests
echo "=========================================="
echo "Suite 5: Metrics and Misc Tests"
echo "Started: $(date)"
echo "=========================================="
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should collect metrics and service CA metrics"
MISC1_RESULT=$?
./bin/service-ca-operator-tests-ext run-test "Service CA Operator should refresh CA when secret is deleted"
MISC2_RESULT=$?
MISC_RESULT=$((MISC1_RESULT + MISC2_RESULT))
echo "Result: Exit code $MISC_RESULT"
echo "Finished: $(date)"

# Summary
echo ""
echo "=========================================="
echo "Test Execution Summary"
echo "=========================================="
echo "Suite 1 - Webhook Injection: $([ $WEBHOOK_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "Suite 2 - CA Rotation:       $([ $ROTATION_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "Suite 3 - Serving Certs:     $([ $SERVING_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "Suite 4 - CA Bundle:         $([ $INJECTION_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "Suite 5 - Metrics/Misc:      $([ $MISC_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "=========================================="

# Exit with error if any suite failed
TOTAL_FAILURES=$((WEBHOOK_RESULT + ROTATION_RESULT + SERVING_RESULT + INJECTION_RESULT + MISC_RESULT))
if [ $TOTAL_FAILURES -eq 0 ]; then
    echo "🎉 All test suites passed!"
    exit 0
else
    echo "⚠️  $TOTAL_FAILURES suite(s) failed"
    exit 1
fi
