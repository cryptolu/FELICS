#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2017 University of Luxembourg
#
# Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>
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

# Set the maximum number fo elements of an array to be printed
set print elements 2000
# Set the threshold for suppressing display of repeated array elements
set print repeats 3000


# Set the analysed stack size in bytes in the convenience variable
set $analysed_stack_size=2000


#
# Set the breakpoints
#
break BeginEncryptionInitialization
break EndEncryptionInitialization

break BeginEncryptionAssociatedDataProcessing
break EndEncryptionAssociatedDataProcessing

break BeginPlaintextProcessing
break EndPlaintextProcessing

break BeginEncryptionFinalization
break EndEncryptionFinalization

break BeginTagGeneration
break EndTagGeneration

break BeginDecryptionInitialization
break EndDecryptionInitialization

break BeginDecryptionAssociatedDataProcessing
break EndDecryptionAssociatedDataProcessing

break BeginCiphertextProcessing
break EndCiphertextProcessing

break BeginDecryptionFinalization
break EndDecryptionFinalization

break BeginTagVerification
break EndTagVerification

# Start the program execution
run


#
# BeginEncryptionInitialization breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


#
# EndEncryptionInitialization breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginEncryptionAssociatedDataProcessing breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


#
# EndEncryptionAssociatedDataProcessing breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginPlaintextProcessing breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


#
# EndPlaintextProcessing breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginEncryptionFinalization breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndEncryptionFinalization breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginTagGeneration breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndTagGeneration breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginDecryptionInitialization breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndDecryptionInitialization breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginDecryptionAssociatedDataProcessing breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndDecryptionAssociatedDataProcessing breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginCiphertextProcessing breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndCiphertextProcessing breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginDecryptionFinalization breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndDecryptionFinalization breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size


# Continue the program execution
continue


# 
# BeginTagVerification breakpoint
#
# Save the initial stack pointer in the convenience variable
set $base = $sp
# Set the stack content
restore PC_scenario0_memory.mem binary $base-$analysed_stack_size


# Continue the program execution
continue


# 
# EndTagVerification breakpoint
#
# Print the stack content in hexa using artificial arrays
print/x *((unsigned char*)$base-$analysed_stack_size)@$analysed_stack_size

# Finish the debugging session
quit
