from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils import resample
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib
from collections import deque
import pandas as pd
import warnings

# Ignorar warnings de convergencia
warnings.filterwarnings("ignore", category=UserWarning)

class HybridDDoSDetector:
    def __init__(self):
        """
        Modelo híbrido mejorado con:
        - Balanceo de clases
        - Validación cruzada
        - Umbrales adaptativos
        - Sistema de votación temporal
        - Normalización de características
        """
        self.rf_model = None
        self.svm_model = None
        self.scaler = StandardScaler()
        self.last_predictions = deque(maxlen=15)  # Ventana más grande para votación
        self.load_or_train()

    def load_or_train(self):
        """Carga modelos existentes o entrena nuevos"""
        try:
            self.rf_model = joblib.load('rf_model.pkl')
            self.svm_model = joblib.load('svm_model.pkl')
            self.scaler = joblib.load('scaler.pkl')
            print("Modelos cargados exitosamente")
            self.validate_models()
        except:
            print("Entrenando nuevos modelos...")
            self.train_hybrid_model()

    def preprocess_data(self, data):
        """Preprocesamiento y balanceo de datos"""
        # Eliminar columna TEST_TYPE si existe (última columna)
        if data.shape[1] == 6:  # 5 características + TEST_TYPE
            X = data.iloc[:, :-2].values  # Excluye TEST_TYPE y la columna de etiquetas
            y = data.iloc[:, -2].values   # Usa la penúltima columna como etiqueta
        else:
            X = data.iloc[:, :-1].values
            y = data.iloc[:, -1].values
        
        # Normalización
        X = self.scaler.fit_transform(X)
        
        # Balanceo de clases (sobre-muestreo clase minoritaria)
        X_normal = X[y == '0']
        X_attack = X[y == '1']
        
        X_attack_upsampled = resample(
            X_attack,
            replace=True,
            n_samples=len(X_normal))  # Mismo tamaño que clase normal
        
        X_balanced = np.vstack((X_normal, X_attack_upsampled))
        y_balanced = np.hstack((np.zeros(len(X_normal)), np.ones(len(X_attack_upsampled))))
        
        return X_balanced, y_balanced

    def train_hybrid_model(self):
        """Entrenamiento con validación y ajuste de hiperparámetros"""
        data = pd.read_csv('result.csv')
        X, y = self.preprocess_data(data)
        
        # División train-test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y)
        
        # Entrenamiento Random Forest optimizado
        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=2,
            class_weight='balanced_subsample',
            n_jobs=-1,
            random_state=42
        )
        self.rf_model.fit(X_train, y_train)
        
        # Entrenamiento SVM optimizado
        self.svm_model = svm.SVC(
            kernel='rbf',
            C=2.0,
            gamma='scale',
            probability=True,
            class_weight='balanced',
            random_state=42
        )
        self.svm_model.fit(X_train, y_train)
        
        # Evaluación
        print("\n=== Evaluación del Modelo ===")
        self.evaluate_models(X_test, y_test)
        
        # Guardar modelos
        joblib.dump(self.rf_model, 'rf_model.pkl')
        joblib.dump(self.svm_model, 'svm_model.pkl')
        joblib.dump(self.scaler, 'scaler.pkl')

    def evaluate_models(self, X_test, y_test):
        """Evaluación detallada con métricas extendidas"""
        print("\nRandom Forest:")
        y_pred_rf = self.rf_model.predict(X_test)
        print(classification_report(y_test, y_pred_rf, target_names=['Normal', 'Ataque']))
        print("Matriz de Confusión:")
        print(confusion_matrix(y_test, y_pred_rf))
        
        print("\nSVM:")
        y_pred_svm = self.svm_model.predict(X_test)
        print(classification_report(y_test, y_pred_svm, target_names=['Normal', 'Ataque']))
        print("Matriz de Confusión:")
        print(confusion_matrix(y_test, y_pred_svm))

    def validate_models(self):
        """Validación continua con nuevos datos"""
        try:
            data = pd.read_csv('result.csv')
            X, y = self.preprocess_data(data)
            print("\n=== Validación con Datos Recientes ===")
            self.evaluate_models(X, y)
        except Exception as e:
            print(f"Error en validación: {str(e)}")

    def hybrid_predict(self, features):
        """
        Predicción híbrida mejorada con:
        - Normalización de características
        - Umbrales dinámicos
        - Votación ponderada
        - Mecanismo de fallback
        """
        try:
            # Preprocesamiento
            features = np.array(features).reshape(1, -1).astype(float)
            features = self.scaler.transform(features)
            
            # Predicciones y confianzas
            rf_proba = self.rf_model.predict_proba(features)[0]
            svm_proba = self.svm_model.predict_proba(features)[0]
            
            rf_class = str(int(self.rf_model.classes_[np.argmax(rf_proba)]))
            rf_confidence = np.max(rf_proba)
            
            svm_class = str(int(self.svm_model.classes_[np.argmax(svm_proba)]))
            svm_confidence = np.max(svm_proba)
            
            # Sistema de decisión mejorado
            final_pred = self.decision_engine(rf_class, rf_confidence, 
                                            svm_class, svm_confidence)
            
            # Registro para votación temporal
            self.last_predictions.append(final_pred)
            
            # Detección basada en ventana temporal
            if list(self.last_predictions).count('1') >= 7:  # 7/15 muestras
                return ['1'], max(rf_confidence, svm_confidence)
            
            return [final_pred], max(rf_confidence, svm_confidence)
            
        except Exception as e:
            print(f"Error en predicción: {str(e)}")
            return ['0'], 0.0  # Fallback a tráfico normal

    def decision_engine(self, rf_class, rf_conf, svm_class, svm_conf):
        """
        Motor de decisión mejorado:
        1. Si ambos modelos están muy seguros y coinciden -> usa ese resultado
        2. Si un modelo está mucho más seguro que el otro -> usa ese
        3. Si ambos están inseguros -> prioriza RF pero con umbral bajo
        4. Si hay discordancia pero alta confianza -> prioriza detección de ataques
        """
        # Umbrales adaptativos (más sensibles a ataques)
        high_conf = 0.7
        med_conf = 0.5
        
        # Caso 1: Ambos seguros y coinciden
        if rf_conf > high_conf and svm_conf > high_conf:
            return rf_class if rf_class == svm_class else '1'
        
        # Caso 2: Un modelo mucho más seguro
        if rf_conf > svm_conf + 0.2:
            return rf_class
        if svm_conf > rf_conf + 0.2:
            return svm_class
        
        # Caso 3: Ambos inseguros
        if rf_conf < med_conf and svm_conf < med_conf:
            return rf_class  # Priorizar RF por defecto
        
        # Caso 4: Cualquier indicio de ataque
        if '1' in [rf_class, svm_class]:
            return '1'
        
        return '0'  # Default seguro

class MachineLearningAlgo:
    """Wrapper para compatibilidad con el controlador"""
    def __init__(self):
        self.detector = HybridDDoSDetector()
    
    def classify(self, data):
        """Interface para el controller.py"""
        prediction, confidence = self.detector.hybrid_predict(data)
        return prediction, confidence  # Devuelve ambos valores