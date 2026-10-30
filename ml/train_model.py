from ml.model_service import train_and_save

if __name__ == "__main__":
    model = train_and_save()
    print("Model trained and saved successfully.")
    print("Scikit-learn version:", __import__("sklearn").__version__)
    print("Classes:", list(model.classes_))
