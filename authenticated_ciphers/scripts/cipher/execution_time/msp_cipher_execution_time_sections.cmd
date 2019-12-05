#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015-2019 University of Luxembourg
#
# Author: Luan Cardoso (2019), Virat Shejwalkar (2017),
#         Daniel Dinu (2015), and Yann Le Corre (2015)
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

# Select the file to debug
prog cipher.elf


#
# Set the breakpoints
#
setbreak Initialize
setbreak EndEncryptionInitialization

setbreak ProcessAssociatedData
setbreak EndEncryptionAssociatedDataProcessing

setbreak ProcessPlaintext
setbreak EndPlaintextProcessing

setbreak Finalize
setbreak EndEncryptionFinalization

setbreak TagGeneration
setbreak EndTagGeneration

# Add the benchmark execution time debug device to the IO's simulator's bus
simio add tracer debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice

#
# delete all previous breakponts and set them again
#
delbreak

setbreak ProcessCiphertext
setbreak EndCiphertextProcessing

setbreak TagVerification
setbreak EndTagVerification

# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice


# Run the program
run
# Print status information for the benchmark execution time debug device
simio info debugDevice

# Exit from simulator
exit
