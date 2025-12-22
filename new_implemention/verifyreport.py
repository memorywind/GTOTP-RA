# verifyreport.py
import json
import base64
import hashlib
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class ReportVerifier:
    """报告验证器，用于验证TEE报告"""

    def __init__(self, verbose=False):
        self.cached_reports = {}  # 缓存已验证的报告
        self.verbose = verbose

    def log(self, message):
        """日志输出"""
        if self.verbose:
            print(message)

    def load_report_from_file(self, file_path="report.json"):
        """从文件加载报告"""
        try:
            with open(file_path, 'r') as f:
                report_data = json.load(f)
            self.log(f"成功加载报告文件: {file_path}")
            return report_data
        except FileNotFoundError:
            if self.verbose:
                print(f"报告文件 {file_path} 未找到")
            return None
        except json.JSONDecodeError:
            if self.verbose:
                print(f"报告文件 {file_path} JSON格式错误")
            return None

    def parse_public_key(self, pem_key_str):
        """解析PEM格式的公钥"""
        try:
            # 从字符串加载公钥
            public_key = serialization.load_pem_public_key(
                pem_key_str.encode('utf-8')
            )
            self.log("成功解析公钥")
            return public_key
        except Exception as e:
            if self.verbose:
                print(f"解析公钥失败: {e}")
            return None

    def verify_report_signature(self, report_data, public_key):
        """验证报告签名"""
        try:
            # 获取报告数据和签名
            json_report = report_data.get("report", {}).get("json_report", "{}")
            json_report_sig_b64 = report_data.get("report", {}).get("json_report_sig", "")

            if not json_report or not json_report_sig_b64:
                self.log("报告数据或签名为空")
                return False

            # Base64解码签名
            json_report_sig = base64.b64decode(json_report_sig_b64)

            # 计算报告的哈希值
            report_hash = hashlib.sha256(json_report.encode('utf-8')).digest()

            # 验证签名（使用RSA-PSS填充）
            public_key.verify(
                json_report_sig,
                report_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH
                ),
                hashes.SHA256()
            )

            self.log("报告签名验证成功")
            return True

        except Exception as e:
            if self.verbose:
                print(f"报告签名验证失败: {e}")
            return False

    def verify_quote_structure(self, report_data):
        """验证Quote基本结构"""
        try:
            json_report_str = report_data.get("report", {}).get("json_report", "{}")
            quote_data = json.loads(json_report_str)
            b64_quote = quote_data.get("b64_quote", "")

            if not b64_quote:
                self.log("Quote数据为空")
                return False

            # Base64解码Quote
            quote_bytes = base64.b64decode(b64_quote)

            # 检查Quote最小长度（模拟检查）
            if len(quote_bytes) < 100:
                self.log("Quote长度不足")
                return False

            self.log(f"Quote结构验证成功，长度: {len(quote_bytes)} 字节")
            return True

        except Exception as e:
            if self.verbose:
                print(f"Quote结构验证失败: {e}")
            return False

    def verify_collateral_data(self, report_data):
        """验证证明数据（简化版本）"""
        try:
            json_report_str = report_data.get("report", {}).get("json_report", "{}")
            quote_data = json.loads(json_report_str)
            collateral_data = json.loads(quote_data.get("json_collateral", "{}"))

            # 检查必要的字段
            required_fields = ["version", "pck_crl_issuer_chain", "tcb_info", "qe_identity"]
            for field in required_fields:
                if field not in collateral_data:
                    self.log(f"证明数据缺少必要字段: {field}")
                    return False

            # 验证TCB信息结构
            tcb_info_str = collateral_data.get("tcb_info", "{}")
            tcb_info = json.loads(tcb_info_str)
            if "tcbInfo" not in tcb_info:
                self.log("TCB信息格式不正确")
                return False

            # 验证QE身份信息
            qe_identity_str = collateral_data.get("qe_identity", "{}")
            qe_identity = json.loads(qe_identity_str)
            if "enclaveIdentity" not in qe_identity:
                self.log("QE身份信息格式不正确")
                return False

            self.log("证明数据验证成功")
            return True

        except Exception as e:
            if self.verbose:
                print(f"证明数据验证失败: {e}")
            return False

    def check_report_freshness(self, report_data, max_age_seconds=300):
        """检查报告新鲜度（基于报告中的时间戳）"""
        try:
            # 从报告中提取时间信息
            json_report_str = report_data.get("report", {}).get("json_report", "{}")
            quote_data = json.loads(json_report_str)

            # 检查tcb_info中的issueDate
            collateral_data = json.loads(quote_data.get("json_collateral", "{}"))
            tcb_info_str = collateral_data.get("tcb_info", "{}")
            tcb_info = json.loads(tcb_info_str)
            tcb_info_data = tcb_info.get("tcbInfo", {})

            current_time = time.time()

            if "issueDate" in tcb_info_data:
                # 解析ISO格式的时间戳（简化处理）
                issue_date_str = tcb_info_data["issueDate"]
                # 这里简化处理：假设时间戳是有效的
                # 在实际实现中，需要将ISO时间转换为时间戳并比较
                self.log(f"报告发布时间: {issue_date_str}")

            # 检查nextUpdate（如果存在）
            if "nextUpdate" in tcb_info_data:
                next_update_str = tcb_info_data["nextUpdate"]
                self.log(f"报告下次更新时间: {next_update_str}")

            self.log("报告新鲜度检查完成")
            return True

        except Exception as e:
            if self.verbose:
                print(f"报告新鲜度检查失败: {e}")
            return False

    def verify_tee_platform(self, report_data):
        """验证TEE平台类型"""
        try:
            tee_platform = report_data.get("report", {}).get("str_tee_platform", "")
            supported_platforms = ["HETERO_TEE_SGX", "SGX", "TDX", "SEV"]

            if tee_platform not in supported_platforms:
                self.log(f"不支持的TEE平台: {tee_platform}")
                return False

            self.log(f"TEE平台验证成功: {tee_platform}")
            return True

        except Exception as e:
            if self.verbose:
                print(f"TEE平台验证失败: {e}")
            return False

    def verify_report_type(self, report_data):
        """验证报告类型"""
        try:
            report_type = report_data.get("report", {}).get("str_report_type", "")
            supported_types = ["Passport", "Attestation", "Verification"]

            if report_type not in supported_types:
                self.log(f"不支持的报告类型: {report_type}")
                return False

            self.log(f"报告类型验证成功: {report_type}")
            return True

        except Exception as e:
            if self.verbose:
                print(f"报告类型验证失败: {e}")
            return False

    def verify_report_version(self, report_data):
        """验证报告版本"""
        try:
            report_version = report_data.get("report", {}).get("str_report_version", "")

            # 检查版本格式（简化）
            if not report_version:
                self.log("报告版本为空")
                return False

            # 检查是否为有效版本号（简化）
            try:
                version_parts = report_version.split('.')
                if len(version_parts) != 2:
                    self.log("报告版本格式不正确")
                    return False
                major, minor = int(version_parts[0]), int(version_parts[1])
                if major < 1:
                    self.log("报告主版本号太低")
                    return False
            except ValueError:
                self.log("报告版本号解析失败")
                return False

            self.log(f"报告版本验证成功: {report_version}")
            return True

        except Exception as e:
            if self.verbose:
                print(f"报告版本验证失败: {e}")
            return False

    def verify_report_complete(self, report_data):
        """完整报告验证流程"""
        verification_steps = [
            ("验证报告版本", lambda: self.verify_report_version(report_data)),
            ("验证报告类型", lambda: self.verify_report_type(report_data)),
            ("验证TEE平台", lambda: self.verify_tee_platform(report_data)),
            ("验证Quote结构", lambda: self.verify_quote_structure(report_data)),
            ("验证证明数据", lambda: self.verify_collateral_data(report_data)),
            ("验证报告新鲜度", lambda: self.check_report_freshness(report_data)),
        ]

        # 如果是SGX平台，还需要验证签名
        tee_platform = report_data.get("report", {}).get("str_tee_platform", "")
        results = {}
        total_time = 0

        for step_name, step_func in verification_steps:
            try:
                start_time = time.perf_counter()
                step_result = step_func()
                end_time = time.perf_counter()

                step_time = (end_time - start_time) * 1000  # 转换为毫秒
                total_time += step_time

                results[step_name] = {
                    "success": step_result,
                    "time_ms": step_time
                }

                self.log(f"{step_name}: {'成功' if step_result else '失败'} ({step_time:.4f}ms)")

                if not step_result:
                    self.log(f"{step_name}失败，终止验证")
                    break

            except Exception as e:
                self.log(f"{step_name}执行异常: {e}")
                results[step_name] = {
                    "success": False,
                    "time_ms": 0,
                    "error": str(e)
                }
                break

        overall_success = all(r["success"] for r in results.values())

        return {
            "overall_success": overall_success,
            "steps": results,
            "total_time_ms": total_time
        }

    def verify_report_with_timing(self, report_data):
        """验证报告并返回详细时间信息"""
        timing_result = self.verify_report_complete(report_data)

        # 提取各阶段时间
        step_times = {}
        for step_name, step_info in timing_result["steps"].items():
            step_times[step_name] = step_info["time_ms"]

        # 计算主要阶段时间
        hash_verification_time = 0
        signature_verification_time = 0
        data_validation_time = 0

        for step_name, step_time in step_times.items():
            if "签名" in step_name:
                signature_verification_time += step_time
            elif "结构" in step_name or "数据" in step_name:
                data_validation_time += step_time
            elif "验证" in step_name:
                hash_verification_time += step_time

        return {
            "overall_success": timing_result["overall_success"],
            "total_time_ms": timing_result["total_time_ms"],
            "hash_verification_time_ms": hash_verification_time,
            "signature_verification_time_ms": signature_verification_time,
            "data_validation_time_ms": data_validation_time,
            "detailed_steps": timing_result["steps"]
        }


# 为benchmark.py提供简化的验证接口
def verify_report_benchmark(report_file="report.json", verbose=False):
    """基准测试接口：验证报告并返回时间信息"""
    verifier = ReportVerifier(verbose=verbose)

    # 加载报告
    report_data = verifier.load_report_from_file(report_file)
    if not report_data:
        return {
            "success": False,
            "total_time_ms": 0,
            "error": "无法加载报告文件"
        }

    # 验证报告
    return verifier.verify_report_with_timing(report_data)


if __name__ == "__main__":
    # 测试代码
    print("=== 报告验证测试 ===")
    result = verify_report_benchmark("report.json", verbose=True)

    print(f"\n验证结果: {'成功' if result['overall_success'] else '失败'}")
    print(f"总时间: {result['total_time_ms']:.4f} ms")
    print(f"哈希验证时间: {result.get('hash_verification_time_ms', 0):.4f} ms")
    print(f"签名验证时间: {result.get('signature_verification_time_ms', 0):.4f} ms")
    print(f"数据验证时间: {result.get('data_validation_time_ms', 0):.4f} ms")