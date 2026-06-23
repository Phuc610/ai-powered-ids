"""
AIThreatDetector - Lõi phân tích an ninh bằng Isolation Forest
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051

Chức năng:
  - extract_features(): Trích xuất đặc trưng từ dữ liệu log
  - train_model(): Huấn luyện Isolation Forest trên dữ liệu lịch sử
  - predict_anomaly(): Phát hiện bất thường và trả về risk_score
"""

import os
import joblib
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.database_connector import DatabaseConnector


logger = logging.getLogger(__name__)


class AIThreatDetector:
    """
    Đóng vai trò "bộ não" trung tâm, chứa thuật toán AI Isolation Forest.

    Attributes:
        isolate_forest_model (IsolationForest): Đối tượng chứa mô hình AI
        risk_threshold (float): Ngưỡng rủi ro quyết định khóa IP (0.0 - 1.0)
    """

    def __init__(self, config: dict, db: DatabaseConnector):
        ai_cfg = config.get("ai", {})
        self.model_path: str = ai_cfg.get("model_path", "data/isolation_forest_model.pkl")
        self.scaler_path: str = self.model_path.replace(".pkl", "_scaler.pkl")
        self.contamination: float = ai_cfg.get("contamination", 0.05)
        self.risk_threshold: float = ai_cfg.get("risk_threshold", 0.6)
        self.min_training_samples: int = ai_cfg.get("min_training_samples", 50)

        self.isolate_forest_model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self.db = db
        self._is_trained = False

        # Thử load model đã train từ trước
        self._load_model()

    def extracts_features(self, log_data: Dict) -> Optional[np.ndarray]:
        """
        Chế biến đặc trưng từ một bản ghi log.

        Feature vector gồm 6 chiều:
        [failed_count_10min, failed_count_60min, success_ratio,
         hour_of_day, is_weekend, unique_usernames_tried]
        
        Args:
            log_data: Dict chứa ip_address, username, event_status, ...
        
        Returns:
            numpy array shape (1, 6) hoặc None nếu không đủ dữ liệu
        """
        ip = log_data.get("ip_address", "")
        if not ip:
            return None

        try:
            # 1. Số lần thất bại trong 10 phút
            failed_10min = self.db.get_failed_login_count(ip, 10)

            # 2. Số lần thất bại trong 60 phút
            failed_60min = self.db.get_failed_login_count(ip, 60)

            # 3. Lấy log gần đây để tính tỷ lệ thành công
            recent_logs = self.db.get_recent_logs(ip, 60) or []
            all_logs = self.db.execute_query(
                """SELECT event_status FROM system_logs 
                   WHERE ip_address = %s 
                   AND logged_at >= NOW() - INTERVAL '60 minutes'""",
                (ip,)
            ) or []

            total = len(all_logs)
            success_count = sum(1 for l in all_logs if l.get('event_status') == 'Success')
            success_ratio = success_count / total if total > 0 else 0.0

            # 4. Giờ trong ngày (0-23)
            hour_of_day = datetime.now().hour

            # 5. Có phải cuối tuần không (0=Thứ 2, 6=CN)
            is_weekend = 1 if datetime.now().weekday() >= 5 else 0

            # 6. Số username khác nhau thử trong 10 phút
            unique_users = self.db.execute_query(
                """SELECT COUNT(DISTINCT username) as cnt FROM system_logs
                   WHERE ip_address = %s 
                   AND logged_at >= NOW() - INTERVAL '10 minutes'""",
                (ip,)
            )
            unique_usernames = unique_users[0]['cnt'] if unique_users else 0

            feature_vector = np.array([[
                failed_10min,
                failed_60min,
                success_ratio,
                hour_of_day,
                is_weekend,
                unique_usernames
            ]], dtype=float)

            return feature_vector

        except Exception as e:
            logger.error(f" Feature extraction error for {ip}: {e}")
            return None

    def _build_training_features(self, history_data: List[Dict]) -> Optional[np.ndarray]:
        """Xây dựng ma trận đặc trưng từ dữ liệu lịch sử để huấn luyện."""
        if not history_data or len(history_data) < self.min_training_samples:
            return None

        df = pd.DataFrame(history_data)

        # Nhóm theo IP và khoảng thời gian
        records = []
        for ip, group in df.groupby("ip_address"):
            total = len(group)
            failed = len(group[group['event_status'] == 'Failed'])
            success = len(group[group['event_status'] == 'Success'])

            # Đếm theo giờ
            group['hour'] = pd.to_datetime(group['logged_at']).dt.hour
            records.append([
                failed,                              # failed_count
                total,                               # total_attempts
                success / total if total > 0 else 0, # success_ratio
                group['hour'].mean(),                # avg_hour
                (pd.to_datetime(group['logged_at']).dt.dayofweek >= 5).mean(),  # weekend_ratio
                group['username'].nunique() if 'username' in group.columns else 1  # unique_users
            ])

        if len(records) < self.min_training_samples // 10:
            return None

        return np.array(records, dtype=float)

    def train_model(self, history_data: List[Dict] = None) -> bool:
        """
        Huấn luyện lại AI model từ dữ liệu lịch sử.

        Args:
            history_data: List các dict log từ DB (None = lấy tự động từ DB)
        
        Returns:
            True nếu training thành công
        """
        if history_data is None:
            history_data = self.db.get_training_data(limit=10000)

        logger.info(f" Training Isolation Forest with {len(history_data)} records...")

        X = self._build_training_features(history_data)
        if X is None:
            logger.warning("  Not enough data to train. Using mock training data...")
            X = self._generate_mock_training_data()

        # Chuẩn hóa features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Huấn luyện Isolation Forest
        self.isolate_forest_model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_jobs=-1
        )
        self.isolate_forest_model.fit(X_scaled)
        self._is_trained = True

        # Lưu model
        self._save_model()

        logger.info(f" Model trained successfully on {len(X)} samples "
                    f"(contamination={self.contamination})")
        return True

    def predict_anomaly(self, new_log: Dict) -> Tuple[bool, float]:
        """
        Trả về giá trị Boolean và risk_score cho một bản ghi log mới.

        Args:
            new_log: Dict chứa thông tin log mới nhất từ một IP

        Returns:
            (is_attack: bool, risk_score: float)
            - is_attack=True nếu là tấn công
            - risk_score: 0.0 (an toàn) → 1.0 (cực kỳ nguy hiểm)
        """
        # Nếu chưa train, train ngay
        if not self._is_trained:
            logger.info(" Model not trained yet. Training now...")
            self.train_model()

        features = self.extracts_features(new_log)
        if features is None:
            return False, 0.0

        try:
            # Chuẩn hóa
            if self._scaler:
                features_scaled = self._scaler.transform(features)
            else:
                features_scaled = features

            # Dự đoán: -1 = anomaly, 1 = normal
            prediction = self.isolate_forest_model.predict(features_scaled)[0]

            # Tính risk_score từ anomaly score
            # score_samples trả về giá trị âm: càng âm = càng bất thường
            raw_score = self.isolate_forest_model.score_samples(features_scaled)[0]

            # Chuyển về thang 0.0 - 1.0
            # raw_score thường nằm trong [-0.5, 0.5]
            risk_score = max(0.0, min(1.0, (0.5 - raw_score)))

            # Rule-based supplement: nếu failed_count_10min > 10 → boost risk
            failed_10min = features[0][0]
            if failed_10min >= 10:
                risk_score = min(1.0, risk_score + 0.3)
            elif failed_10min >= 5:
                risk_score = min(1.0, risk_score + 0.15)

            is_attack = (prediction == -1) and (risk_score >= self.risk_threshold)
            
            # Đảm bảo chặn cứng nếu quá 5 lần (vượt ngưỡng rule_based)
            if failed_10min >= 5:
                is_attack = True
                risk_score = max(risk_score, 0.8)

            ip = new_log.get("ip_address", "unknown")
            if is_attack:
                logger.warning(f" THREAT DETECTED: {ip} | risk_score={risk_score:.3f} | "
                               f"failed_10min={int(failed_10min)}")
            else:
                logger.debug(f" Normal: {ip} | risk_score={risk_score:.3f}")

            return is_attack, round(risk_score, 4)

        except Exception as e:
            logger.error(f" Prediction error: {e}")
            # Fallback: rule-based detection
            return self._rule_based_detection(new_log)

    def _rule_based_detection(self, log_data: Dict) -> Tuple[bool, float]:
        """Phát hiện tấn công thuần túy bằng rule (fallback khi AI lỗi)."""
        ip = log_data.get("ip_address", "")
        failed_10min = self.db.get_failed_login_count(ip, 10)

        if failed_10min >= 10:
            return True, 0.9
        elif failed_10min >= 5:
            return True, 0.75
        elif failed_10min >= 3:
            return False, 0.4
        return False, 0.1

    def _generate_mock_training_data(self) -> np.ndarray:
        """Tạo dữ liệu training mẫu khi DB chưa đủ dữ liệu."""
        np.random.seed(42)
        n_normal = 400
        n_attack = 20

        # Normal behavior: ít failed, tỷ lệ success cao
        normal = np.column_stack([
            np.random.poisson(0.5, n_normal),     # failed_10min (thấp)
            np.random.poisson(1.0, n_normal),     # failed_60min
            np.random.uniform(0.7, 1.0, n_normal), # success_ratio (cao)
            np.random.randint(8, 18, n_normal),   # hour (giờ làm việc)
            np.zeros(n_normal),                    # is_weekend
            np.ones(n_normal),                     # unique_usernames (1)
        ])

        # Attack behavior: nhiều failed, tỷ lệ success thấp, nhiều username
        attacks = np.column_stack([
            np.random.randint(10, 100, n_attack),  # failed_10min (cao)
            np.random.randint(50, 500, n_attack),  # failed_60min
            np.zeros(n_attack),                    # success_ratio (0)
            np.random.randint(0, 24, n_attack),    # hour (bất kỳ)
            np.random.randint(0, 2, n_attack),     # is_weekend
            np.random.randint(5, 50, n_attack),    # unique_usernames (nhiều)
        ])

        return np.vstack([normal, attacks])

    def _save_model(self):
        """Lưu model và scaler ra file."""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            if self.isolate_forest_model:
                joblib.dump(self.isolate_forest_model, self.model_path)
            if self._scaler:
                joblib.dump(self._scaler, self.scaler_path)
            logger.info(f" Model saved: {self.model_path}")
        except Exception as e:
            logger.error(f" Failed to save model: {e}")

    def _load_model(self):
        """Load model đã train từ file nếu có."""
        try:
            if os.path.exists(self.model_path):
                self.isolate_forest_model = joblib.load(self.model_path)
                if os.path.exists(self.scaler_path):
                    self._scaler = joblib.load(self.scaler_path)
                self._is_trained = True
                logger.info(f" Pre-trained model loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"  Could not load model: {e}")

    def get_model_info(self) -> Dict:
        """Trả về thông tin về model hiện tại."""
        return {
            "is_trained": self._is_trained,
            "model_path": self.model_path,
            "contamination": self.contamination,
            "risk_threshold": self.risk_threshold,
            "n_estimators": self.isolate_forest_model.n_estimators if self._is_trained else 0,
        }
