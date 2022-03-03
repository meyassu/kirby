"""
TODO:
- get src/dest IP
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
import numpy as np
import json
import os

# Constants
DATA_DIR = "data/"

# Set device for neural net
device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using {device} device")

# Hyperparameters
torch.manual_seed(42)
BATCH_SIZE = 64
SHUFFLE = True
NUM_WORKERS = 6
MAX_EPOCHS = 100


"""
The following classes and functions are concerned with data ingestion.
"""

class NetworkFlowDataset(Dataset):
	def __init__(self, fname):
		"""
		pass data_fpath=train.json if train or test.json if test
		"""
		self.fname = os.path.join(DATA_DIR, fname)

		def __len__(self):
			"""
			Returns the number of elements in the dataset

			:return: (int) -> the dataset length
			"""

			return len(self.flows)

		def __getitem__(self, idx):
			"""
			Gets the requested item from JSON data file.
			The JSON has the following nested structure:
			{
				"Training" OR "Testing": [
					{
						"packets" = [p_0, ....., p_n] where each p_i is a bit string
						"Tag": "t"
					}

					{
						packets = [p_0, ....., p_n] where each p_i is a bit string
						"Tag": "t"
					}
					.
					.
					.
				         ]

			}
			It is a single object consisting of an array of objects composed of (packet, tag) pairs.			

			:param idx: (int) -> the index

			:return: (pckts, tag) -> returns the binary packet representation and its corresponding tag; tag=None on test dataset
			"""

			# read data
			with open(self.data_fpath, "r") as infile:
				data = json.load(infile)
			data = data[fname.split("/")[1].split(".")[0]]
			datum = data[idx]
			pckts = np.asarray(datum["packets"])
			# use mapping here
			
			# get tag
			if "train" in self.data_fpath:
				tag = datum["Tag"]
			else:
				tag = None

			return pckts, tag

"""
The following classes and functions are concered with model training and inference.
"""

class NetworkFlow():
	"""
	A network flow.
	"""
	def __init__(self, pckts, src_ip, dest_ip, src_port, dest_port):
		"""
		Initializes a network flow.

		:param pckts: (np.ndarray) -> array of packets where each packet is represented as a binary string (shape=(222,222))
		:param src_ip: (str) -> the source ip
		:param dest_ip: (str) -> the destination ip
		:param src_port: (str) -> the source port
		:param dest_port: (str) -> the destination port
		"""

		self.pckts = pckts
		self.src_ip = src_ip
		self.dest_ip = dest_ip
		self.src_port = src_port
		self.dest_port = dest_port

class NeuralNetwork(nn.Module):
	def __init__(self):
		super(NeuralNetwork, self).__init__()
		self.flatten = nn.Flatten()
		self.linear_relu_stack = nn.Sequential(
	    	nn.Linear(28*28, 512),
	    	nn.ReLU(),
	    	nn.Linear(512, 512),
	    	nn.ReLU(),
	    	nn.Linear(512, 10),
		)

	def forward(self, x):
		x = self.flatten(x)
		logits = self.linear_relu_stack(x)
		return logits



def train(model, optimizer, data_fname, model_fpath):
	"""
	Trains the model.

	:param model: (torch.nn) -> the model
	:param optimizer: (torch.optim) -> the optimizer
	:param epochs: number of epochs
	:param training_data: ()
	"""

	# load data
	train_params = {"batch_size:" BATCH_SIZE,
					"shuffle": SHUFFLE
					"num_workers": NUM_WORKERS
				   }
	
	train_data = Dataset(data_fname)
	train_loader = DataLoader(train_data, **params)

	# train model
	model.train()
	loss_function = nn.NLLLoss()
	for epoch in range(MAX_EPOCHS):
		print(f"Starting epoch {epoch}...")
		for batch, labels, in train_loader:
			model.zero_grad()
			# transfer to GPU
			batch, labels = batch.to(device), labels.to(device)

		for sentence, tags in training_data:
			model.zero_grad()

			# Step 2. Get our inputs ready for the network, that is, turn them into
			# Tensors of word indices.
			# Eventually I suggest you use the DataLoader modules
			# The batching can take place here
			sentence_in = prepare_sequence(sentence, word_to_ix)
			targets = prepare_sequence(tags, tag_to_ix)

			# Step 3. Run our forward pass.
			tag_scores = model(sentence_in)

			# Step 4. Compute the loss, gradients, and update the parameters by
			#  calling optimizer.step()
			loss = loss_function(tag_scores, targets)
			loss.backward()
			optimizer.step()

	# Save model
	checkpoint = {
		"epoch": epoch + 1,
		"model_state_dict": model.state_dict(),
		"optimizer_state_dict": optimizer.state_dict()
	}
	save_checkpoint(checkpoint=checkpoint, is_best=False, checkpoint_fpath=checkpoint_fpath, best_model_fpath=best_model_fpath)


def run(model, data):

	

	# # construct network flow
	# # start/end indices for port fields
	# src_port_start, src_port_end = 0, 16
	# dest_port_start, dest_port_end = 17, 32

	# src_ip, dest_ip = None, None
	# f_packet = pckts[0]
	# src_port = int(f_packet[src_port_start:src_port_end+1], 2)
	# dest_port = int(f_packet[dest_port_start:dest_port_end+1], 2)
	# flow = NetworkFlow(datum["packets"], src_ip, dest_ip, src_port, dest_port)


"""
The following functions are concerned with the AE-firewall IPC interface.
"""
"""
The grammar for AE-firewall communications can be described like this:
Vocabulary: actions, target_types, targets
- actions: the set of all the possible things the firewall can do : {b, p, d} // block, pass, deny
- target_types: the set of all possible types of targets : {sip, sport} // source IP, source port
- targets: the set of all numbers of some fixed length, it is the actual numerical identifier of the type of target 
  (e.g. if target_type=src IP, then target would be the actual address) : {0,9}^n

A rule can be stored in a dictionary and, in general, looks like this: <action: a, target_type: t, target: T, sip (optional): sip>
We might want to propose multiple rules at once so we can store these tuples in a list. We can call a list of rules a rule set.
An rule set in its general form looks like this: [rule_0,...,rule_n] 

Note: when proposing a rule that blocks the source port, also include the source IP in the rule

e.g. if the firewall should block the source IP 192.168.13.14 and destination port 80, the rule_set would look like:
[
	{
		action: b,
		target_type: sip,
		target: 192.168.13.14,
		sip: None
	}

	{
		action: b,
		target_type: sport,
		target: 80,
		sip: 192.168.13.14
	}
]
"""

def generate_rules(attack, flow):
	"""
	Generate rules based on the attack type and the metadata contained in flow.

	:param attack: (str) -> the type of attack (e.g. DOS)
	:param flow: (NetworkFlow) -> NetworkFlow object

	:return: (list(tuples)) -> a rule set
	"""

	rule_set = []
	
	if attack == "dos":
		rule_set.append( {"action": "b", "target_type":"sip", "target": flow.src_ip} )
		rule_set.append( {"action": "b", "target_type":"sport", "target": flow.src_port} )
	elif attack == "infiltrating_transfer":
		pass

	return rule_set

def transmit_rule(rules):
	"""
	Transmit proposed rules to the firewall in JSON format. 

	:param rules: (list(tuples)) -> the proposed rules

	:return: (bool) -> transmission outcome
	"""

	pass






















