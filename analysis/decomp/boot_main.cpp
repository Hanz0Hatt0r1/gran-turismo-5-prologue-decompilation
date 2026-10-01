// Partial clean-room pseudocode reconstructed from BCUS-98158 EBOOT.BIN.
// This is intentionally not buildable yet. Unknown helpers retain descriptive
// working names rather than invented SDK/API signatures.

#include <cstdint>

namespace gt5p::bootstrap {

constexpr uint32_t kPfs2Magic = 0x5B745162;
constexpr int32_t kGameDataBroken = static_cast<int32_t>(0x8002B606u);
constexpr uint16_t kFsSysmodule = 0x000e;

enum class BootState : int {
    Initial = 0,
    GameData = 1,
    Failed = 2,
};

// Working reconstruction of 0x106A0.
bool path_exists(const char* path)
{
    PathQueryResult tmp{};
    return path_query(path, &tmp) == 0;
}

// Working reconstruction of 0x10640.
bool paths_match_after_normalization(const char* lhs, char* rhs)
{
    normalize_path(rhs);
    return path_compare(lhs, rhs) == 0;
}

// 0x10610.
void handle_broken_game_data()
{
    cellGameDataExitBroken();
    game_data_cleanup();
}

// 0x106E0.
// Names below describe observed behavior, not recovered original identifiers.
int boot_main(int argc, char** argv)
{
    runtime_bootstrap_init();

    // Several runtime/argument subsystems are initialized here.
    RuntimeScope runtime_scope{};
    runtime_scope.initialize();
    initialize_process_arguments(&argc, argv);

    auto* launch_a = get_cached_launch_object_a();
    auto* launch_b = get_cached_launch_object_b();
    auto* boot = get_boot_state();

    fixed_path_assign(boot->disc_usrdir, "/dev_bdvd/PS3_GAME/USRDIR");

    PfsHeaderCandidate disc_header{};
    read_or_build_pfs_header(
        disc_header,
        launch_b,
        "/dev_bdvd/PS3_GAME/USRDIR/GT.VOL",
        0);

    int game_data_error = 0;
    bool game_data_ok = check_game_data_paths(
        launch_a,
        boot->game_data_path_a,
        sizeof(boot->game_data_path_a),
        boot->game_data_path_b,
        sizeof(boot->game_data_path_b),
        &game_data_error);

    if (!game_data_ok) {
        if (game_data_error == kGameDataBroken) {
            handle_broken_game_data();
            // Observed state transition at 0x10CFC.
            return -1;
        }

        // Other asynchronous/not-ready results remain in the bootstrap
        // state machine. Exact state names are still under reconstruction.
    }

    BootState state = BootState::Initial;

    // Paths derived from the base launch directory:
    FixedPath emain_path = make_path(launch_a, "EMAIN.SELF");
    FixedPath epatch_path = make_path(launch_a, "EPATCH.SELF");
    FixedPath updating_path = make_path(launch_a, "UPDATING");

    FixedPath pdipfs_path = make_path(launch_a);
    pdipfs_path.append("/PDIPFS/");
    pdipfs_path.append(make_pdipfs_component(1));

    FixedPath alternate_pdipfs_path = make_path(launch_a);
    alternate_pdipfs_path.append("/PDIPFS/");
    alternate_pdipfs_path.append(make_pdipfs_component(2));

    // The observed decision tree uses file existence plus normalized-path
    // comparison to decide whether patch/game-data launch is valid.
    if (path_exists(updating_path.c_str())) {
        // fall through to volume validation
    } else if (path_exists(epatch_path.c_str()) &&
               paths_match_after_normalization(epatch_path.c_str(),
                                               emain_path.c_str())) {
        state = BootState::GameData;
    } else if (path_exists(alternate_pdipfs_path.c_str())) {
        if (paths_match_after_normalization(alternate_pdipfs_path.c_str(),
                                            pdipfs_path.c_str())) {
            // volume validation path
        } else {
            handle_broken_game_data();
            return -1;
        }
    }

    PfsHeaderCandidate candidate{};
    read_or_build_pfs_header(candidate, launch_b, pdipfs_path.c_str(), 0);

    if (candidate.magic != kPfs2Magic) {
        // Re-enters the failure / state-machine path.
        return -1;
    }

    // Additional header/sequence comparisons follow. A larger/equal
    // sequence condition selects game-data boot and copies the resolved
    // game-data path into the active boot path.
    if (pfs_candidate_is_acceptable(candidate, disc_header)) {
        if (state == BootState::GameData) {
            bounded_copy(boot->active_path,
                         boot->game_data_path_b,
                         sizeof(boot->active_path));
            boot->boot_source = "boot_from=gamedata";
        }
    }

    // State strings are written through a global launch/configuration slot:
    //   Initial  -> "install_condition=need_patch_update"
    //   GameData -> "install_condition=need_nothing"

    while (!boot_state_poll_a()) {
        // asynchronous startup work
    }

    cellSysmoduleInitialize();
    cellSysmoduleLoadModule(kFsSysmodule);

    // The code constructs an EMAIN.SELF path before the final handoff.
    // An alternate branch invokes an internal launch wrapper with the same
    // priority/flag pair.
    prepare_next_self_path(emain_path);

    // Direct imported handoff observed at 0x10D20.
    sys_game_process_exitspawn2(
        launch_a,
        launch_b,
        nullptr,
        nullptr,
        nullptr,
        1001,
        64);

    while (boot_state_poll_b()) {
        // Alternate launch wrapper path can execute here.
    }

    return 0;
}

} // namespace gt5p::bootstrap
