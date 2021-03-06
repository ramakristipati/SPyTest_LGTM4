import pytest
import lib_mclag_stp as lib_stp
from spytest import st

vars = dict()
stp_protocol = "rpvst"
topology_2_tier = False
topology_scale = True

@pytest.fixture(scope="module", autouse=True)
def mclag_stp_interaction_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1D3:40", "D1D4:1", "D1D5:1", "D2D4:40", "D2D3:1", "D3D4:3", "D3D5:1", "D4D5:1", "D1T1:1", "D2T1:1", "D3T1:1", "D4T1:1", "D5T1:1")
    lib_stp.module_config(vars, stp_protocol, topology_2_tier, topology_scale)
    yield
    lib_stp.module_unconfig(stp_protocol)

@pytest.fixture(scope="function", autouse=True)
def mclag_stp_interaction_function_hooks(request):
    lib_stp.update_log_error_flag(True)

    yield

    lib_stp.update_log_error_flag(False)
    lib_stp.check_setup_status()

def test_ft_rpvst_scale_mclag_convergence():
    if lib_stp.lib_stp_mclag_basic_tests():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_interface_shut_noshut():
    if lib_stp.lib_stp_mclag_interface_shutdown():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_disable_enable_stp():
    if lib_stp.lib_stp_mclag_disable_enable_stp():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_failover():
    if lib_stp.lib_stp_mclag_failover_tests():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_active_and_standby_failover():
    if lib_stp.lib_stp_mclag_both_peers_reload():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_active_and_standby_config_reload():
    if lib_stp.lib_stp_mclag_config_reload():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_all_intf_shut_noshut():
    if lib_stp.lib_stp_mclag_all_intf_shut_noshut():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_scale_mclag_vlan_participation_del_add():
    if lib_stp.lib_stp_mclag_vlan_participation_del_add():
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')