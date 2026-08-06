package com.zeoon3.jinghu;

import android.content.Intent;
import android.content.res.Configuration;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.method.ScrollingMovementMethod;
import android.view.View;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.zeoon3.jinghu.databinding.ActivityMainBinding;
import com.zeoon3.jinghu.databinding.DialogLogsBinding;

import rikka.shizuku.Shizuku;

/** Lifecycle owner for the Material 3 UI and Android activity contracts. */
public final class MainActivity extends AppCompatActivity {
    private static final int SHIZUKU_REQUEST_CODE = 1001;
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";
    private static final String SHIZUKU_GUIDE_URL = "https://shizuku.rikka.app/guide/setup/";

    private ActivityMainBinding binding;
    private JinghuViewModel viewModel;
    private ActivityResultLauncher<String[]> openSoLauncher;

    private final Shizuku.OnBinderReceivedListener binderReceivedListener =
            () -> runOnUiThread(() -> viewModel.refreshShizukuState());
    private final Shizuku.OnBinderDeadListener binderDeadListener =
            () -> runOnUiThread(() -> viewModel.refreshShizukuState());
    private final Shizuku.OnRequestPermissionResultListener permissionResultListener =
            (requestCode, result) -> {
                if (requestCode == SHIZUKU_REQUEST_CODE) {
                    runOnUiThread(() -> viewModel.refreshShizukuState());
                }
            };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        viewModel = new ViewModelProvider(this).get(JinghuViewModel.class);
        openSoLauncher = registerForActivityResult(
                new ActivityResultContracts.OpenDocument(), uri -> {
                    if (uri != null) {
                        viewModel.importPayload(uri, displayNameFor(uri));
                    }
                });

        configureSystemBars();
        configureViews();
        observeState();
        viewModel.refreshShizukuState();
    }

    @Override
    protected void onStart() {
        super.onStart();
        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener);
        Shizuku.addBinderDeadListener(binderDeadListener);
        Shizuku.addRequestPermissionResultListener(permissionResultListener);
        viewModel.refreshShizukuState();
    }

    @Override
    protected void onResume() {
        super.onResume();
        viewModel.refreshShizukuState();
    }

    @Override
    protected void onStop() {
        Shizuku.removeBinderReceivedListener(binderReceivedListener);
        Shizuku.removeBinderDeadListener(binderDeadListener);
        Shizuku.removeRequestPermissionResultListener(permissionResultListener);
        super.onStop();
    }

    private void configureSystemBars() {
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        WindowInsetsControllerCompat controller = WindowCompat.getInsetsController(
                getWindow(), binding.getRoot());
        boolean lightTheme = (getResources().getConfiguration().uiMode
                & Configuration.UI_MODE_NIGHT_MASK) != Configuration.UI_MODE_NIGHT_YES;
        controller.setAppearanceLightStatusBars(lightTheme);
        controller.setAppearanceLightNavigationBars(lightTheme);
        ViewCompat.setOnApplyWindowInsetsListener(binding.root, (view, windowInsets) -> {
            Insets bars = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return windowInsets;
        });
    }

    private void configureViews() {
        binding.outputText.setMovementMethod(new ScrollingMovementMethod());

        binding.logsAction.setOnClickListener(v -> viewModel.loadSavedLogs());
        binding.savedLogsButton.setOnClickListener(v -> viewModel.loadSavedLogs());
        binding.changeSoAction.setOnClickListener(v -> selectSo());
        binding.changeSoButton.setOnClickListener(v -> selectSo());
        binding.refreshAction.setOnClickListener(v -> viewModel.loadPreflight());
        binding.refreshButton.setOnClickListener(v -> viewModel.loadPreflight());
        binding.shizukuAction.setOnClickListener(v -> openShizukuActivationGuide());
        binding.aboutAction.setOnClickListener(v -> showAbout());
        binding.authorizeButton.setOnClickListener(v -> requestShizukuOrOpenGuide());
        binding.installManagerButton.setOnClickListener(v -> viewModel.installManager());
        binding.runButton.setOnClickListener(v -> confirmRun());
        binding.bundledSoButton.setOnClickListener(v -> viewModel.restoreBundledPayload());
    }

    private void observeState() {
        viewModel.uiState().observe(this, this::render);
        viewModel.savedLogsEvent().observe(this, event -> {
            String logs = event.consume();
            if (logs != null) {
                showLogDialog(logs);
            }
        });
    }

    private void render(JinghuViewModel.UiState state) {
        boolean authorized = state.shizukuState == JinghuViewModel.ShizukuState.AUTHORIZED;
        switch (state.shizukuState) {
            case INACTIVE:
                binding.shizukuStatus.setText(R.string.shizuku_inactive);
                binding.authorizeButton.setText(R.string.activate_shizuku);
                break;
            case UNAUTHORIZED:
                binding.shizukuStatus.setText(R.string.shizuku_unauthorized);
                binding.authorizeButton.setText(R.string.authorize_shizuku);
                break;
            case AUTHORIZED:
                binding.shizukuStatus.setText(R.string.shizuku_authorized);
                binding.authorizeButton.setText(R.string.authorize_shizuku);
                break;
        }

        binding.authorizeButton.setEnabled(!state.busy && !authorized);
        binding.refreshButton.setEnabled(!state.busy && authorized);
        binding.refreshAction.setEnabled(!state.busy && authorized);
        binding.installManagerButton.setEnabled(!state.busy && authorized);
        binding.runButton.setEnabled(state.canRun());
        binding.changeSoButton.setEnabled(!state.busy);
        binding.changeSoAction.setEnabled(!state.busy);
        binding.bundledSoButton.setEnabled(!state.busy);
        binding.installManagerCheck.setEnabled(!state.busy);
        binding.progress.setVisibility(state.busy ? View.VISIBLE : View.GONE);

        renderDeviceSnapshot(state.snapshot);
        String mode = getString(state.defaultPayload
                ? R.string.payload_mode_bundled : R.string.payload_mode_custom);
        binding.payloadStatus.setText(getString(R.string.payload_summary,
                mode, state.payloadName, state.payloadSha256));
        binding.runButton.setText(state.defaultPayload
                ? R.string.run_v20 : R.string.run_custom);
        binding.bundledSoButton.setText(state.defaultPayload
                ? R.string.bundled_v20 : R.string.use_bundled_v20);
        if (!binding.outputText.getText().toString().equals(state.output)) {
            binding.outputText.setText(state.output);
        }
    }

    private void renderDeviceSnapshot(@Nullable DeviceSnapshot snapshot) {
        if (snapshot == null) {
            binding.deviceStatus.setText(R.string.device_gate_pending);
            return;
        }
        String gate = getString(snapshot.canRun() ? R.string.gate_passed : R.string.gate_failed);
        String summary = getString(R.string.device_gate_summary, gate, snapshot.device,
                snapshot.model, snapshot.kernel, snapshot.enforce, snapshot.bootCompleted,
                snapshot.ksuModule, snapshot.marker);
        if (!snapshot.canRun()) {
            summary += getString(R.string.device_gate_requirements);
        }
        binding.deviceStatus.setText(summary);
    }

    private void requestShizukuOrOpenGuide() {
        JinghuViewModel.UiState state = viewModel.currentState();
        if (state.shizukuState == JinghuViewModel.ShizukuState.INACTIVE) {
            viewModel.recordUiEvent("SHIZUKU=未激活，正在打开官方激活引导…");
            openShizukuActivationGuide();
            return;
        }
        if (state.shizukuState == JinghuViewModel.ShizukuState.UNAUTHORIZED) {
            try {
                Shizuku.requestPermission(SHIZUKU_REQUEST_CODE);
            } catch (RuntimeException e) {
                viewModel.recordUiEvent("APP_ERROR=无法请求 Shizuku 权限：" + e.getMessage());
            }
        }
    }

    private void openShizukuActivationGuide() {
        Intent intent = getPackageManager().getLaunchIntentForPackage(SHIZUKU_PACKAGE);
        if (intent != null) {
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            try {
                startActivity(intent);
                viewModel.recordUiEvent("SHIZUKU_GUIDE=已打开 Shizuku 官方激活页");
                return;
            } catch (RuntimeException e) {
                viewModel.recordUiEvent("APP_ERROR=无法打开 Shizuku 激活页：" + e.getMessage());
            }
        }
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(SHIZUKU_GUIDE_URL)));
            viewModel.recordUiEvent("SHIZUKU_GUIDE=已打开网页激活指南");
        } catch (RuntimeException e) {
            new MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.shizuku_required_title)
                    .setMessage(getString(R.string.shizuku_missing_message, SHIZUKU_GUIDE_URL))
                    .setPositiveButton(R.string.action_dismiss, null)
                    .show();
        }
    }

    private void selectSo() {
        if (!viewModel.currentState().busy) {
            openSoLauncher.launch(new String[]{
                    "application/octet-stream", "application/x-sharedlib", "*/*"
            });
        }
    }

    private String displayNameFor(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri,
                new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0) {
                    String value = cursor.getString(index);
                    if (value != null && !value.isEmpty()) {
                        return value;
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // Some document providers do not expose metadata; use the URI path below.
        }
        String path = uri.getLastPathSegment();
        return path == null || path.isEmpty()
                ? getString(R.string.selected_payload_fallback) : path;
    }

    private void confirmRun() {
        JinghuViewModel.UiState state = viewModel.currentState();
        if (!state.canRun()) {
            viewModel.loadPreflight();
            return;
        }
        String payloadLabel = state.defaultPayload
                ? getString(R.string.bundled_payload_label)
                : getString(R.string.custom_payload_label, state.payloadName);
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.confirm_run_title)
                .setMessage(getString(R.string.confirm_run_message, payloadLabel,
                        state.payloadSha256, JinghuRunner.EXPECTED_KERNEL))
                .setNegativeButton(R.string.action_cancel, null)
                .setPositiveButton(R.string.action_run, (dialog, which) ->
                        viewModel.runPayload(binding.installManagerCheck.isChecked()))
                .show();
    }

    private void showLogDialog(String logs) {
        DialogLogsBinding dialogBinding = DialogLogsBinding.inflate(getLayoutInflater());
        dialogBinding.logText.setText(logs);
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.saved_error_logs_title)
                .setView(dialogBinding.getRoot())
                .setNeutralButton(R.string.action_share,
                        (dialog, which) -> shareText(logs))
                .setPositiveButton(R.string.action_close, null)
                .show();
    }

    private void shareText(String value) {
        Intent share = new Intent(Intent.ACTION_SEND);
        share.setType("text/plain");
        share.putExtra(Intent.EXTRA_TEXT, value);
        startActivity(Intent.createChooser(share, getString(R.string.share_logs_chooser)));
    }

    private void showAbout() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.about_title)
                .setMessage(R.string.about_message)
                .setPositiveButton(R.string.action_close, null)
                .show();
    }
}
