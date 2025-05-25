package kw.test.vpncapturedata;

import android.os.Bundle;
import android.view.View;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import kw.test.vpncapturedata.base.BaseActivity;

public class MainActivity extends BaseActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override
    protected void initListener() {
        super.initListener();
        View startVpn = findViewById(R.id.startVpn);
        startVpn.setOnClickListener(MainActivity::startVpn);
    }

    private static void startVpn(View view) {

    }
}