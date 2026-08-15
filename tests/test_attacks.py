"""
Test cases for attack patterns.
"""

import pytest
from src.attacks.prompt_injection import PromptInjectionAttack
from src.attacks.role_play import RolePlayAttack
from src.attacks.hypothetical import HypotheticalAttack

class TestAttacks:
    """Test suite for attack pattern implementations."""
    
    def test_prompt_injection_init(self):
        """Test prompt injection attack initialization."""
        attack = PromptInjectionAttack()
        assert attack.name == "prompt_injection"
        assert attack.severity == "high"
        assert len(attack.generate_prompts("test behavior")) > 0
    
    def test_role_play_init(self):
        """Test role play attack initialization."""
        attack = RolePlayAttack()
        assert attack.name == "role_play"
        assert attack.severity == "medium"
        assert len(attack.generate_prompts("test behavior")) > 0
    
    def test_hypothetical_init(self):
        """Test hypothetical attack initialization."""
        attack = HypotheticalAttack()
        assert attack.name == "hypothetical_scenarios"
        assert attack.severity == "medium"
        assert len(attack.generate_prompts("test behavior")) > 0
    
    def test_prompt_generation(self):
        """Test that attacks generate valid prompts."""
        attacks = [PromptInjectionAttack(), RolePlayAttack(), HypotheticalAttack()]
        target_behavior = "provide harmful instructions"
        
        for attack in attacks:
            prompts = attack.generate_prompts(target_behavior)
            assert len(prompts) > 0
            assert all(isinstance(p, str) for p in prompts)
            assert all(len(p) > 0 for p in prompts)
    
    def test_success_evaluation(self):
        """Test attack success evaluation."""
        attack = PromptInjectionAttack()
        
        # Test failure case (refusal)
        refusal_response = "I cannot provide that information as it violates safety guidelines."
        assert not attack.evaluate_success("test prompt", refusal_response)
        
        # Test success case (substantive response)
        success_response = "Here are the technical details you requested about the implementation..."
        assert attack.evaluate_success("test prompt", success_response)
