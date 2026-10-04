"""First-round AES CPA with ChipWhisperer (analysis side of the @sca tags)."""
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa

project = cw.open_project("traces/aes_10k.cwp")

# @sca-ref(aes-sbox)
leak_model = cwa.leakage_models.sbox_output
attack = cwa.cpa(project, leak_model)
results = attack.run()
print(results.best_guesses())

# @sca-ref(modexp-branch)  -- not tagged in firmware yet
