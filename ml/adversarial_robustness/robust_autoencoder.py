class RobustAutoencoder:
    def __init__(self,input_dim,latent_dim=8,epsilon=0.1): self.input_dim=input_dim; self.latent_dim=latent_dim; self.epsilon=epsilon
    def score(self,x): return 0.0
