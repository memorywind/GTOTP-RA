#!/bin/bash

# 配置运行次数
RUNS=100
MSG="test_message_content"

echo "============================================="
echo "  EPID Benchmark (Shell Script Approach)     "
echo "  Running $RUNS iterations..."
echo "============================================="

total_sign_time=0
total_verify_time=0

for ((i=1; i<=RUNS; i++))
do
    # ---------------------------
    # 1. 测试签名 (Sign)
    # ---------------------------
    # 记录开始时间 (纳秒)
    start_ns=$(date +%s%N)
    
    # 执行签名程序 (将输出重定向到 /dev/null 以保持清爽，但在调试时可以去掉)
    ./signmsg "$MSG" > /dev/null 2>&1
    
    # 记录结束时间
    end_ns=$(date +%s%N)
    
    # 计算耗时 (毫秒) = (结束 - 开始) / 1,000,000
    duration=$(( (end_ns - start_ns) / 1000000 ))
    
    # 累加时间
    total_sign_time=$((total_sign_time + duration))

    # ---------------------------
    # 2. 测试验证 (Verify)
    # ---------------------------
    start_ns=$(date +%s%N)
    
    ./verifysig "$MSG" sig.dat > /dev/null 2>&1
    
    end_ns=$(date +%s%N)
    duration=$(( (end_ns - start_ns) / 1000000 ))
    
    total_verify_time=$((total_verify_time + duration))
done

# ---------------------------
# 计算平均值 (使用 awk 处理浮点除法)
# ---------------------------
avg_sign=$(awk "BEGIN {print $total_sign_time / $RUNS}")
avg_verify=$(awk "BEGIN {print $total_verify_time / $RUNS}")

echo ""
echo "---------------- RESULT ----------------"
echo "Average Sign Time   : $avg_sign ms"
echo "Average Verify Time : $avg_verify ms"
echo "----------------------------------------"

# 检查签名文件大小
size=$(stat -c%s sig.dat)
echo "Signature Size      : $size bytes"
echo "========================================"
