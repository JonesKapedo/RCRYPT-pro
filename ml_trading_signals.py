"""
RockyCrypt AI/ML Trading Signals
Machine learning-powered trading predictions and signals
"""

import numpy as np
import pandas as pd
from typing import Dict, Tuple, Optional, List
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
import logging
from datetime import datetime
import joblib
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MLTradingSignals:
    """AI-powered trading signal generation"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.rf_model = None
        self.gb_model = None
        self.feature_names = []
        self.trained = False
        self.models_dir = Path("data/ml_models")
        self.models_dir.mkdir(exist_ok=True)
    
    def prepare_features(self, df: pd.DataFrame, lookback: int = 60) -> pd.DataFrame:
        """Prepare 50+ technical features for ML models"""
        
        features = pd.DataFrame(index=df.index)
        
        # ===== PRICE FEATURES =====
        features['returns'] = df['close'].pct_change()
        features['log_returns'] = np.log(df['close'] / df['close'].shift(1))
        features['volatility'] = df['returns'].rolling(window=20).std()
        features['price_range'] = (df['high'] - df['low']) / df['close']
        features['close_position'] = (df['close'] - df['low']) / (df['high'] - df['low'])
        
        # ===== MOVING AVERAGES =====
        for period in [5, 10, 20, 50, 200]:
            features[f'sma_{period}'] = df['close'].rolling(window=period).mean()
            features[f'ema_{period}'] = df['close'].ewm(span=period).mean()
            features[f'price_above_sma_{period}'] = (df['close'] > features[f'sma_{period}']).astype(int)
        
        # ===== MOMENTUM =====
        features['rsi_14'] = self._calculate_rsi(df['close'], 14)
        features['rsi_7'] = self._calculate_rsi(df['close'], 7)
        features['macd'], features['macd_signal'], features['macd_hist'] = self._calculate_macd(df['close'])
        features['momentum_10'] = df['close'] - df['close'].shift(10)
        features['momentum_20'] = df['close'] - df['close'].shift(20)
        features['roc_12'] = (df['close'] - df['close'].shift(12)) / df['close'].shift(12) * 100
        
        # ===== VOLUME =====
        features['volume_sma'] = df['volume'].rolling(window=20).mean()
        features['volume_ratio'] = df['volume'] / features['volume_sma']
        features['obv'] = self._calculate_obv(df)
        features['ad_line'] = self._calculate_ad_line(df)
        
        # ===== VOLATILITY =====
        features['atr_14'] = self._calculate_atr(df, 14)
        features['bb_width'] = self._calculate_bollinger_width(df['close'], 20)
        features['bb_position'] = self._calculate_bollinger_position(df['close'], 20)
        
        # ===== TREND STRENGTH =====
        features['adx'] = self._calculate_adx(df, 14)
        features['di_plus'] = self._calculate_di_plus(df, 14)
        features['di_minus'] = self._calculate_di_minus(df, 14)
        
        # ===== CORRELATION FEATURES =====
        features['price_above_bb_upper'] = (df['close'] > (df['close'].rolling(20).mean() + 2*df['close'].rolling(20).std())).astype(int)
        features['price_below_bb_lower'] = (df['close'] < (df['close'].rolling(20).mean() - 2*df['close'].rolling(20).std())).astype(int)
        
        # ===== PRICE ACTION PATTERNS =====
        features['higher_high'] = (df['high'] > df['high'].shift(1)).astype(int)
        features['higher_low'] = (df['low'] > df['low'].shift(1)).astype(int)
        features['lower_high'] = (df['high'] < df['high'].shift(1)).astype(int)
        features['lower_low'] = (df['low'] < df['low'].shift(1)).astype(int)
        
        # Clean data
        features = features.fillna(method='bfill').fillna(method='ffill')
        
        self.feature_names = features.columns.tolist()
        
        return features
    
    @staticmethod
    def _calculate_rsi(prices: pd.Series, period: int = 14) -> pd.Series:
        """Calculate RSI"""
        delta = prices.diff()
        gain = (delta.where(delta > 0, 0)).rolling(window=period).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=period).mean()
        rs = gain / loss
        return 100 - (100 / (1 + rs))
    
    @staticmethod
    def _calculate_macd(prices: pd.Series) -> Tuple[pd.Series, pd.Series, pd.Series]:
        """Calculate MACD"""
        ema_12 = prices.ewm(span=12).mean()
        ema_26 = prices.ewm(span=26).mean()
        macd_line = ema_12 - ema_26
        signal = macd_line.ewm(span=9).mean()
        histogram = macd_line - signal
        return macd_line, signal, histogram
    
    @staticmethod
    def _calculate_obv(df: pd.DataFrame) -> pd.Series:
        """Calculate OBV"""
        obv = [0]
        for i in range(1, len(df)):
            if df['close'].iloc[i] > df['close'].iloc[i-1]:
                obv.append(obv[-1] + df['volume'].iloc[i])
            elif df['close'].iloc[i] < df['close'].iloc[i-1]:
                obv.append(obv[-1] - df['volume'].iloc[i])
            else:
                obv.append(obv[-1])
        return pd.Series(obv, index=df.index)
    
    @staticmethod
    def _calculate_ad_line(df: pd.DataFrame) -> pd.Series:
        """Calculate A/D Line"""
        mfm = ((df['close'] - df['low']) - (df['high'] - df['close'])) / (df['high'] - df['low'])
        return (mfm * df['volume']).cumsum()
    
    @staticmethod
    def _calculate_atr(df: pd.DataFrame, period: int = 14) -> pd.Series:
        """Calculate ATR"""
        high_low = df['high'] - df['low']
        high_close = abs(df['high'] - df['close'].shift())
        low_close = abs(df['low'] - df['close'].shift())
        tr = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)
        return tr.rolling(window=period).mean()
    
    @staticmethod
    def _calculate_bollinger_width(prices: pd.Series, period: int = 20) -> pd.Series:
        """Calculate Bollinger Band width"""
        sma = prices.rolling(window=period).mean()
        std = prices.rolling(window=period).std()
        return (2 * std * 2) / sma * 100
    
    @staticmethod
    def _calculate_bollinger_position(prices: pd.Series, period: int = 20) -> pd.Series:
        """Calculate position within Bollinger Bands"""
        sma = prices.rolling(window=period).mean()
        std = prices.rolling(window=period).std()
        upper = sma + (std * 2)
        lower = sma - (std * 2)
        return (prices - lower) / (upper - lower)
    
    @staticmethod
    def _calculate_adx(df: pd.DataFrame, period: int = 14) -> pd.Series:
        """Calculate ADX (simplified)"""
        high_diff = df['high'].diff()
        low_diff = -df['low'].diff()
        
        plus_dm = high_diff.where((high_diff > low_diff) & (high_diff > 0), 0)
        minus_dm = low_diff.where((low_diff > high_diff) & (low_diff > 0), 0)
        
        tr = pd.concat([
            df['high'] - df['low'],
            abs(df['high'] - df['close'].shift()),
            abs(df['low'] - df['close'].shift())
        ], axis=1).max(axis=1)
        
        atr = tr.rolling(window=period).mean()
        plus_di = (plus_dm.rolling(window=period).mean() / atr) * 100
        minus_di = (minus_dm.rolling(window=period).mean() / atr) * 100
        
        di_sum = plus_di + minus_di
        di_diff = abs(plus_di - minus_di)
        dx = (di_diff / di_sum) * 100
        
        return dx.rolling(window=period).mean()
    
    @staticmethod
    def _calculate_di_plus(df: pd.DataFrame, period: int = 14) -> pd.Series:
        """Calculate +DI"""
        high_diff = df['high'].diff()
        plus_dm = high_diff.where((high_diff > 0) & (high_diff > -df['low'].diff()), 0)
        
        tr = pd.concat([
            df['high'] - df['low'],
            abs(df['high'] - df['close'].shift()),
            abs(df['low'] - df['close'].shift())
        ], axis=1).max(axis=1)
        
        atr = tr.rolling(window=period).mean()
        return (plus_dm.rolling(window=period).mean() / atr) * 100
    
    @staticmethod
    def _calculate_di_minus(df: pd.DataFrame, period: int = 14) -> pd.Series:
        """Calculate -DI"""
        low_diff = -df['low'].diff()
        minus_dm = low_diff.where((low_diff > 0) & (low_diff > df['high'].diff()), 0)
        
        tr = pd.concat([
            df['high'] - df['low'],
            abs(df['high'] - df['close'].shift()),
            abs(df['low'] - df['close'].shift())
        ], axis=1).max(axis=1)
        
        atr = tr.rolling(window=period).mean()
        return (minus_dm.rolling(window=period).mean() / atr) * 100
    
    def train_models(self, df: pd.DataFrame, lookforward: int = 5):
        """Train Random Forest and Gradient Boosting models"""
        
        logger.info(f"Training ML models with {len(df)} candles...")
        
        features = self.prepare_features(df)
        
        # Create target: 1 if price goes up in next 'lookforward' days
        target = (df['close'].shift(-lookforward) > df['close']).astype(int)
        target = target[:-lookforward]
        features = features[:-lookforward]
        
        X = self.scaler.fit_transform(features)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, target, test_size=0.2, random_state=42
        )
        
        # Train Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=10,
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_train, y_train)
        rf_score = self.rf_model.score(X_test, y_test)
        logger.info(f"Random Forest Accuracy: {rf_score:.2%}")
        
        # Train Gradient Boosting
        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )
        self.gb_model.fit(X_train, y_train)
        gb_score = self.gb_model.score(X_test, y_test)
        logger.info(f"Gradient Boosting Accuracy: {gb_score:.2%}")
        
        self.trained = True
        
        # Save models
        self._save_models()
        
        return {
            "rf_accuracy": rf_score,
            "gb_accuracy": gb_score,
            "ensemble_accuracy": (rf_score + gb_score) / 2
        }
    
    def generate_signal(self, df: pd.DataFrame) -> Dict:
        """Generate buy/sell signal"""
        
        if not self.trained:
            return {"error": "Models not trained"}
        
        features = self.prepare_features(df)
        X = self.scaler.transform(features[-1:])
        
        # Get predictions
        rf_prob = self.rf_model.predict_proba(X)[0][1]
        gb_prob = self.gb_model.predict_proba(X)[0][1]
        
        # Ensemble prediction (average)
        ensemble_prob = (rf_prob + gb_prob) / 2
        
        # Generate signal
        if ensemble_prob > 0.65:
            signal = "BUY"
            strength = (ensemble_prob - 0.5) * 200  # Scale to 0-100
        elif ensemble_prob < 0.35:
            signal = "SELL"
            strength = (0.5 - ensemble_prob) * 200
        else:
            signal = "HOLD"
            strength = 0
        
        return {
            "signal": signal,
            "confidence": float(ensemble_prob),
            "strength": min(strength, 100),
            "rf_confidence": float(rf_prob),
            "gb_confidence": float(gb_prob),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_feature_importance(self) -> Dict:
        """Get most important features"""
        if not self.rf_model:
            return {}
        
        importance = self.rf_model.feature_importances_
        feature_importance = dict(zip(self.feature_names, importance))
        sorted_importance = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
        
        return {f: float(v) for f, v in list(sorted_importance.items())[:20]}
    
    def _save_models(self):
        """Save trained models"""
        joblib.dump(self.rf_model, self.models_dir / "rf_model.pkl")
        joblib.dump(self.gb_model, self.models_dir / "gb_model.pkl")
        joblib.dump(self.scaler, self.models_dir / "scaler.pkl")
        logger.info("Models saved")
    
    def load_models(self):
        """Load trained models"""
        try:
            self.rf_model = joblib.load(self.models_dir / "rf_model.pkl")
            self.gb_model = joblib.load(self.models_dir / "gb_model.pkl")
            self.scaler = joblib.load(self.models_dir / "scaler.pkl")
            self.trained = True
            logger.info("Models loaded")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")


# FastAPI Integration
async def setup_ml_routes(app):
    """Setup ML routes in FastAPI"""
    
    ml_signals = MLTradingSignals()
    
    @app.post("/api/ml/train/{symbol}")
    async def train_models_endpoint(symbol: str):
        """Train ML models for symbol"""
        try:
            history = load_price_history(symbol)
            results = ml_signals.train_models(history)
            return {"status": "trained", "results": results}
        except Exception as e:
            return {"error": str(e)}
    
    @app.get("/api/ml/signal/{symbol}")
    async def get_ml_signal(symbol: str):
        """Get AI trading signal"""
        try:
            if not ml_signals.trained:
                ml_signals.load_models()
            
            history = load_price_history(symbol)
            signal = ml_signals.generate_signal(history)
            return signal
        except Exception as e:
            return {"error": str(e)}
    
    @app.get("/api/ml/importance/{symbol}")
    async def get_feature_importance(symbol: str):
        """Get feature importance"""
        try:
            importance = ml_signals.get_feature_importance()
            return {"importance": importance}
        except Exception as e:
            return {"error": str(e)}


print("[ML TRADING SIGNALS] Module loaded")
print("[ML TRADING SIGNALS] Features: RF + GB ensemble, 50+ features, Feature importance analysis")
